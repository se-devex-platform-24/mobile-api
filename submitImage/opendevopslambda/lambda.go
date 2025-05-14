package opendevopslambda

import (
	"math"
	"time"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	maxRetries = 3
	multipartThreshold = 5 * 1024 * 1024 // 5MB threshold for multipart upload
)

type Dependency struct {
	DepS3 s3iface.S3API
	DepDynamoDB dynamodbiface.DynamoDBAPI
}

// retryWithExponentialBackoff implements exponential backoff retry logic
func retryWithExponentialBackoff(operation func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		if err = operation(); err == nil {
			return nil
		}
		// Exponential backoff: 100ms, 200ms, 400ms
		time.Sleep(time.Duration(100*(1<<i)) * time.Millisecond)
	}
	return err
}

var bucketRootName = "open-devops-images"

func (d *Dependency) processRequest(imageUrl string, region string, aws_account_id string) (string, error) {
	response, err := http.Get(imageUrl)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return "", errors.New(fmt.Sprintf("response.StatusCode %d != 200\n", response.StatusCode))
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	bucketName := fmt.Sprintf("%s-%s-%s", bucketRootName, region, aws_account_id)

	imageUuid, uuidErr := uuid.NewRandom()
	if uuidErr != nil {
		return "", uuidErr
	}

	// Determine if we should use multipart upload based on file size
	if len(data) > multipartThreshold {
		// Initialize multipart upload
		createInput := &s3.CreateMultipartUploadInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(imageUuid.String()),
		}
		
		multipartUpload, err := d.DepS3.CreateMultipartUpload(createInput)
		if err != nil {
			return "", fmt.Errorf("failed to initialize multipart upload: %v", err)
		}

		// Upload parts
		partSize := int64(5 * 1024 * 1024) // 5MB parts
		buffer := bytes.NewReader(data)
		var parts []*s3.CompletedPart
		partNum := int64(1)

		for position := int64(0); position < int64(len(data)); position += partSize {
			partSize := int64(math.Min(float64(partSize), float64(int64(len(data))-position)))
			
			partInput := &s3.UploadPartInput{
				Body:          io.NewSectionReader(buffer, position, partSize),
				Bucket:        aws.String(bucketName),
				Key:          aws.String(imageUuid.String()),
				PartNumber:    aws.Int64(partNum),
				UploadId:     multipartUpload.UploadId,
			}

			// Retry logic for part upload
			var partOutput *s3.UploadPartOutput
			err = retryWithExponentialBackoff(func() error {
				var err error
				partOutput, err = d.DepS3.UploadPart(partInput)
				return err
			})
			
			if err != nil {
				// Abort multipart upload on failure
				_, abortErr := d.DepS3.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
					Bucket:   aws.String(bucketName),
					Key:      aws.String(imageUuid.String()),
					UploadId: multipartUpload.UploadId,
				})
				if abortErr != nil {
					return "", fmt.Errorf("failed to abort multipart upload: %v after upload error: %v", abortErr, err)
				}
				return "", fmt.Errorf("failed to upload part %d: %v", partNum, err)
			}

			parts = append(parts, &s3.CompletedPart{
				ETag:       partOutput.ETag,
				PartNumber: aws.Int64(partNum),
			})
			partNum++
		}

		// Complete multipart upload
		completeInput := &s3.CompleteMultipartUploadInput{
			Bucket:   aws.String(bucketName),
			Key:      aws.String(imageUuid.String()),
			UploadId: multipartUpload.UploadId,
			MultipartUpload: &s3.CompletedMultipartUpload{
				Parts: parts,
			},
		}

		_, err = d.DepS3.CompleteMultipartUpload(completeInput)
		if err != nil {
			return "", fmt.Errorf("failed to complete multipart upload: %v", err)
		}
	} else {
		// Regular upload for smaller files
		s3Input := &s3.PutObjectInput{
			Body:   bytes.NewReader(data),
			Bucket: aws.String(bucketName),
			Key:    aws.String(imageUuid.String()),
		}

		// Retry logic for regular upload
		err = retryWithExponentialBackoff(func() error {
			_, err := d.DepS3.PutObject(s3Input)
			return err
		})
		if err != nil {
			return "", fmt.Errorf("failed to upload file: %v", err)
		}
	}

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

	// Add retry logic for DynamoDB operations
	err = retryWithExponentialBackoff(func() error {
		_, err := d.DepDynamoDB.PutItem(dynamoInput)
		if err != nil {
			// Check for provisioned throughput exceeded
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == dynamodb.ErrCodeProvisionedThroughputExceededException {
				return fmt.Errorf("throughput exceeded, retrying: %v", err)
			}
		}
		return err
	})
	if err != nil {
		return "", fmt.Errorf("failed to store item in DynamoDB: %v", err)
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
	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
  aws_account_id := strings.Split(lc.InvokedFunctionArn, ":")[4]

	urlParam, found := request.QueryStringParameters["url"]
	if found {
		urlVal, err := url.QueryUnescape(urlParam)
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: 500,
				Body: `{"ImageId":"error"}`,
				IsBase64Encoded: false,
			}, err
		}

		if !isValidExtension(urlVal) {
			return events.APIGatewayProxyResponse{StatusCode: 500,
				Body: `{"ImageId":"error"}`,
				IsBase64Encoded: false,
			}, errors.New("file extension %s is not valid")
		}

		processString, processErr := d.processRequest(urlVal, region, aws_account_id)
		return events.APIGatewayProxyResponse{StatusCode: 200,
			Body: fmt.Sprintf(`"ImageId":"%s"`, processString),
			IsBase64Encoded: false,
		}, processErr
	}

	return events.APIGatewayProxyResponse{StatusCode: 500,
		Body: `{"ImageId":"error"}`,
		IsBase64Encoded: false,
	}, errors.New("url parameter not found")
}
