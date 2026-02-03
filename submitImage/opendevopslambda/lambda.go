package opendevopslambda

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Constants for configuration
const (
	MaxRetries = 3
	MultipartUploadThreshold = 5 * 1024 * 1024 // 5MB
	MaxTimeout = 30 * time.Second
)

type Dependency struct {
	DepS3        s3iface.S3API
	DepDynamoDB  dynamodbiface.DynamoDBAPI
	httpClient   *http.Client
	AuthHandlers interface{} // Will be *auth.AuthHandlers but avoiding import cycle
}

// NewDependency creates a new Dependency with optimized clients
func NewDependency(s3Client s3iface.S3API, dynamoClient dynamodbiface.DynamoDBAPI) *Dependency {
	return &Dependency{
		DepS3:       s3Client,
		DepDynamoDB: dynamoClient,
		httpClient: &http.Client{
			Timeout: MaxTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

var bucketRootName = "open-devops-images"

func (d *Dependency) processRequest(ctx context.Context, imageUrl string, region string, aws_account_id string) (string, error) {
	// Create request with context for timeout control
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageUrl, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	response, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download image: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if len(data) == 0 {
		return "", errors.New("empty response body")
	}

	bucketName := fmt.Sprintf("%s-%s-%s", bucketRootName, region, aws_account_id)

	imageUuid, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}

	// Use multipart upload for large files
	var s3err error
	if len(data) > MultipartUploadThreshold {
		input := &s3.CreateMultipartUploadInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(imageUuid.String()),
		}
		
		// Create multipart upload
		result, err := d.DepS3.CreateMultipartUploadWithContext(ctx, input)
		if err != nil {
			return "", fmt.Errorf("failed to create multipart upload: %w", err)
		}

		// Upload parts
		partInput := &s3.UploadPartInput{
			Bucket:     aws.String(bucketName),
			Key:        aws.String(imageUuid.String()),
			UploadId:   result.UploadId,
			PartNumber: aws.Int64(1),
			Body:       bytes.NewReader(data),
		}

		partOutput, err := d.DepS3.UploadPartWithContext(ctx, partInput)
		if err != nil {
			// Abort multipart upload on error
			_, abortErr := d.DepS3.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(bucketName),
				Key:      aws.String(imageUuid.String()),
				UploadId: result.UploadId,
			})
			if abortErr != nil {
				return "", fmt.Errorf("failed to abort multipart upload: %v (original error: %w)", abortErr, err)
			}
			return "", fmt.Errorf("failed to upload part: %w", err)
		}

		// Complete multipart upload
		completeInput := &s3.CompleteMultipartUploadInput{
			Bucket:   aws.String(bucketName),
			Key:      aws.String(imageUuid.String()),
			UploadId: result.UploadId,
			MultipartUpload: &s3.CompletedMultipartUpload{
				Parts: []*s3.CompletedPart{
					{
						ETag:       partOutput.ETag,
						PartNumber: aws.Int64(1),
					},
				},
			},
		}

		_, s3err = d.DepS3.CompleteMultipartUploadWithContext(ctx, completeInput)
	} else {
		// Use regular upload for small files
		s3Input := &s3.PutObjectInput{
			Body:   bytes.NewReader(data),
			Bucket: aws.String(bucketName),
			Key:    aws.String(imageUuid.String()),
		}

		_, s3err = d.DepS3.PutObjectWithContext(ctx, s3Input)
	}

	if s3err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", s3err)
	}

	// DynamoDB operation with retry
	dynamoInput := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(imageUuid.String()),
			},
			"Label": {
				S: aws.String("NOT_CLASSIFIED"),
			},
		},
		TableName: aws.String("ImageLabels"),
	}

	// Implement retry logic for DynamoDB
	var dynamoErr error
	for retries := 0; retries <= MaxRetries; retries++ {
		_, dynamoErr = d.DepDynamoDB.PutItemWithContext(ctx, dynamoInput)
		if dynamoErr == nil {
			break
		}
		
		if retries < MaxRetries {
			// Exponential backoff
			time.Sleep(time.Duration(1<<uint(retries)) * time.Second)
		}
	}

	if dynamoErr != nil {
		return "", fmt.Errorf("failed to store in DynamoDB after %d retries: %w", MaxRetries, dynamoErr)
	}

	return imageUuid.String(), nil
}

func isValidExtension(urlVal string) bool {
	validExtensions := []string{"jpeg", "jpg", "bmp", "png", "tiff", "gif", "tif"}

	urlSlice := strings.Split(urlVal, "/")
	fileName := urlSlice[len(urlSlice)-1]
	fileNameSlice := strings.Split(fileName, ".")
	fileExtension := fileNameSlice[len(fileNameSlice)-1]

	for _, ext := range validExtensions {
		if fileExtension == ext {
			return true
		}
	}
	return false
}

func (d *Dependency) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Check if this is an authentication request
	if strings.HasPrefix(request.Path, "/auth/") {
		if d.AuthHandlers != nil {
			// Use type assertion to call the auth handler
			if authHandlers, ok := d.AuthHandlers.(interface {
				RouteRequest(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)
			}); ok {
				return authHandlers.RouteRequest(ctx, request)
			}
		}
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusNotFound,
			Body: `{"error":"authentication service not available"}`,
			IsBase64Encoded: false,
		}, nil
	}

	// Handle image submission (existing functionality)
	return d.handleImageSubmission(ctx, request)
}

func (d *Dependency) handleImageSubmission(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, MaxTimeout)
	defer cancel()

	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
	aws_account_id := strings.Split(lc.InvokedFunctionArn, ":")[4]

	urlParam, found := request.QueryStringParameters["url"]
	if !found {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body: `{"error":"url parameter not found"}`,
			IsBase64Encoded: false,
		}, nil
	}

	urlVal, err := url.QueryUnescape(urlParam)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body: fmt.Sprintf(`{"error":"invalid url: %s"}`, err.Error()),
			IsBase64Encoded: false,
		}, nil
	}

	if !isValidExtension(urlVal) {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body: `{"error":"invalid file extension"}`,
			IsBase64Encoded: false,
		}, nil
	}

	processString, processErr := d.processRequest(ctx, urlVal, region, aws_account_id)
	if processErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusGatewayTimeout,
				Body: `{"error":"request timeout"}`,
				IsBase64Encoded: false,
			}, nil
		}
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body: fmt.Sprintf(`{"error":"%s"}`, processErr.Error()),
			IsBase64Encoded: false,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body: fmt.Sprintf(`{"ImageId":"%s"}`, processString),
		IsBase64Encoded: false,
	}, nil
}
