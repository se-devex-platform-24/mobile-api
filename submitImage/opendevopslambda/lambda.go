package opendevopslambda

import (
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
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Dependency struct {
	DepS3 s3iface.S3API
	DepDynamoDB dynamodbiface.DynamoDBAPI
	RedisClient *redis.Client
}

// Initialize Redis client
func NewDependency(s3Client s3iface.S3API, dynamoClient dynamodbiface.DynamoDBAPI) *Dependency {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
		PoolSize: 1000, // Support high concurrency
	})

	return &Dependency{
		DepS3:       s3Client,
		DepDynamoDB: dynamoClient,
		RedisClient: redisClient,
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.Getenv(key); exists {
		return value
	}
	return defaultValue
}

var bucketRootName = "open-devops-images"

func (d *Dependency) processRequest(imageUrl string, region string, aws_account_id string) (string, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("image:%s", imageUrl)
	if cachedID, err := d.RedisClient.Get(context.Background(), cacheKey).Result(); err == nil {
		return cachedID, nil
	}

	// Create HTTP client with timeout and connection pooling
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Implement retry with exponential backoff
	var response *http.Response
	var err error
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		response, err = client.Get(imageUrl)
		if err == nil && response.StatusCode == 200 {
			break
		}
		if err != nil {
			time.Sleep(time.Duration(math.Pow(2, float64(i))) * time.Second)
			continue
		}
		if response.StatusCode != 200 {
			err = fmt.Errorf("response.StatusCode %d != 200", response.StatusCode)
			time.Sleep(time.Duration(math.Pow(2, float64(i))) * time.Second)
			continue
		}
	}
	if err != nil {
		return "", fmt.Errorf("failed after %d retries: %v", maxRetries, err)
	}
	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
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

	_, s3err := d.DepS3.PutObject(s3Input)
	if s3err != nil {
		return "", s3err
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

	// Implement DynamoDB retry with exponential backoff
	var dynamoErr error
	maxDynamoRetries := 3
	for i := 0; i < maxDynamoRetries; i++ {
		_, dynamoErr = d.DepDynamoDB.PutItem(dynamoInput)
		if dynamoErr == nil {
			break
		}
		if i < maxDynamoRetries-1 {
			time.Sleep(time.Duration(math.Pow(2, float64(i))) * time.Second)
		}
	}
	if dynamoErr != nil {
		return "", fmt.Errorf("DynamoDB operation failed after %d retries: %v", maxDynamoRetries, dynamoErr)
	}

	// Cache the result
	ctx := context.Background()
	cacheKey := fmt.Sprintf("image:%s", imageUrl)
	err = d.RedisClient.Set(ctx, cacheKey, imageUuid.String(), 24*time.Hour).Err()
	if err != nil {
		// Log cache error but don't fail the request
		fmt.Printf("Failed to cache result: %v\n", err)
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
