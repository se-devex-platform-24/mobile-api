package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
	"log"
	"os"
	"submit-image/opendevopslambda"

	"github.com/aws/aws-lambda-go/lambda"
)

func init() {
	log.SetOutput(os.Stdout)
}

func main() {
	// Configure session with max retries and timeouts
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			MaxRetries: aws.Int(5),
			HTTPClient: &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					MaxIdleConns:        100,
					MaxIdleConnsPerHost: 100,
					MaxConnsPerHost:     100,
					IdleConnTimeout:     90 * time.Second,
					TLSHandshakeTimeout: 10 * time.Second,
				},
			},
		},
	}))

	// Configure DynamoDB client with optimized settings
	dynamoDBClient := dynamodb.New(sess, &aws.Config{
		MaxRetries: aws.Int(5),
	})

	// Configure S3 client with optimized settings
	s3Client := s3.New(sess, &aws.Config{
		MaxRetries: aws.Int(3),
	})

	d := opendevopslambda.Dependency{
		DepS3:       s3Client,
		DepDynamoDB: dynamoDBClient,
	}

	lambda.Start(d.Handler)
}
