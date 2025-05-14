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
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"sync"
)

type Dependency struct {
	DepS3        s3iface.S3API
	DepDynamoDB  dynamodbiface.DynamoDBAPI
	RedisClient  *redis.Client
	httpClient   *http.Client
}

var (
	bucketRootName = "open-devops-images"
	// HTTP client configuration
	httpTimeout    = 30 * time.Second
	maxRetries     = 3
	retryInterval  = 1 * time.Second
	
	// Cache configuration
	cacheExpiration = 24 * time.Hour
	
	// Connection pool
	httpTransport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
)

func (d *Dependency) processRequest(ctx context.Context, imageUrl string, region string, aws_account_id string) (string, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("image:%s", imageUrl)
	if d.RedisClient != nil {
		if cachedID, err := d.RedisClient.Get(ctx, cacheKey).Result(); err == nil {
			return cachedID, nil
		}
	}

	// Create HTTP request with context and timeout
	req, err := http.NewRequestWithContext(ctx, "GET", imageUrl, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Implement retry logic for HTTP requests
	var response *http.Response
	for attempt := 0; attempt < maxRetries; attempt++ {
		response, err = d.httpClient.Do(req)
		if err == nil && response.StatusCode == 200 {
			break
		}
		if err != nil {
			if attempt < maxRetries-1 {
				time.Sleep(retryInterval * time.Duration(attempt+1))
				continue
			}
			return "", fmt.Errorf("failed to fetch image after %d attempts: %w", maxRetries, err)
		}
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	bucketName := fmt.Sprintf("%s-%s-%s", bucketRootName, region, aws_account_id)

	imageUuid, uuidErr := uuid.NewRandom()
	if uuidErr != nil {
		return "", uuidErr
	}

	s3Input := &s3.PutObjectInput{
		Body:   bytes.NewReader(data),
		Bucket: aws.String(bucketName),
		Key:    aws.String(imageUuid.String()),
	}

	// Upload to S3 with retry logic
	s3ctx := context.Background()
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, s3err := d.DepS3.PutObjectWithContext(s3ctx, s3Input)
		if s3err == nil {
			break
		}
		if attempt == maxRetries-1 {
			return "", fmt.Errorf("failed to upload to S3 after %d attempts: %w", maxRetries, s3err)
		}
		time.Sleep(retryInterval * time.Duration(attempt+1))
	}

	// Prepare DynamoDB item
	dynamoInput := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(imageUuid.String()),
			},
			"Label": {
				S: aws.String("NOT_CLASSIFIED"),
			},
			"CreatedAt": {
				N: aws.String(fmt.Sprintf("%d", time.Now().Unix())),
			},
		},
		TableName: aws.String("ImageLabels"),
	}

	// Write to DynamoDB with retry logic
	dynamoctx := context.Background()
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, dynamoErr := d.DepDynamoDB.PutItemWithContext(dynamoctx, dynamoInput)
		if dynamoErr == nil {
			break
		}
		if attempt == maxRetries-1 {
			return "", fmt.Errorf("failed to write to DynamoDB after %d attempts: %w", maxRetries, dynamoErr)
		}
		time.Sleep(retryInterval * time.Duration(attempt+1))
	}

	// Store in cache
	if d.RedisClient != nil {
		cacheKey := fmt.Sprintf("image:%s", imageUuid.String())
		if err := d.RedisClient.Set(ctx, cacheKey, imageUuid.String(), cacheExpiration).Err(); err != nil {
			// Log cache error but don't fail the request
			fmt.Printf("Cache write error: %v\n", err)
		}
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
	// Set timeout for the entire operation
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
	aws_account_id := strings.Split(lc.InvokedFunctionArn, ":")[4]

	// Initialize HTTP client if not already initialized
	if d.httpClient == nil {
		d.httpClient = &http.Client{
			Transport: httpTransport,
			Timeout:   httpTimeout,
		}
	}

	urlParam, found := request.QueryStringParameters["url"]
	if !found {
		return events.APIGatewayProxyResponse{
			StatusCode:      400,
			Body:           `{"error":"url parameter not found"}`,
			IsBase64Encoded: false,
		}, nil
	}

	urlVal, err := url.QueryUnescape(urlParam)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode:      400,
			Body:           fmt.Sprintf(`{"error":"invalid url format: %s"}`, err.Error()),
			IsBase64Encoded: false,
		}, nil
	}

	if !isValidExtension(urlVal) {
		return events.APIGatewayProxyResponse{
			StatusCode:      400,
			Body:           `{"error":"invalid file extension"}`,
			IsBase64Encoded: false,
		}, nil
	}

	// Check cache for the URL
	if d.RedisClient != nil {
		cacheKey := fmt.Sprintf("url:%s", urlVal)
		if cachedID, err := d.RedisClient.Get(ctx, cacheKey).Result(); err == nil {
			return events.APIGatewayProxyResponse{
				StatusCode:      200,
				Body:           fmt.Sprintf(`{"ImageId":"%s","cached":true}`, cachedID),
				IsBase64Encoded: false,
			}, nil
		}
	}

	processString, processErr := d.processRequest(ctx, urlVal, region, aws_account_id)
	if processErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return events.APIGatewayProxyResponse{
				StatusCode:      504,
				Body:           `{"error":"request timeout"}`,
				IsBase64Encoded: false,
			}, nil
		}
		return events.APIGatewayProxyResponse{
			StatusCode:      500,
			Body:           fmt.Sprintf(`{"error":"%s"}`, processErr.Error()),
			IsBase64Encoded: false,
		}, nil
	}

	// Cache the result
	if d.RedisClient != nil {
		cacheKey := fmt.Sprintf("url:%s", urlVal)
		if err := d.RedisClient.Set(ctx, cacheKey, processString, cacheExpiration).Err(); err != nil {
			// Log cache error but don't fail the request
			fmt.Printf("Cache write error: %v\n", err)
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode:      200,
		Body:           fmt.Sprintf(`{"ImageId":"%s","cached":false}`, processString),
		IsBase64Encoded: false,
	}, nil
}
