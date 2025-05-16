package opendevopslambda

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"testing"
)

type mockedPutOjbect struct {
	s3iface.S3API
	Response s3.PutObjectOutput
}

type mockedPutItem struct {
	dynamodbiface.DynamoDBAPI
	Response dynamodb.PutItemOutput
}

func (d mockedPutOjbect) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return &d.Response, nil
}

func (d mockedPutItem) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	return &d.Response, nil
}

func TestHandler(t *testing.T) {
	t.Run("Load Test - Concurrent Requests", func(t *testing.T) {
		mpo := mockedPutOjbect{
			Response: s3.PutObjectOutput{},
		}

		mpi := mockedPutItem{
			Response: dynamodb.PutItemOutput{},
		}

		d := Dependency{
			DepS3:       mpo,
			DepDynamoDB: mpi,
		}

		ctx := context.Background()
		lc := new(lambdacontext.LambdaContext)
		lc.InvokedFunctionArn = "arn:aws:lambda:region:123456789000:function:functionName"
		ctx = lambdacontext.NewContext(ctx, lc)

		// Test concurrent requests
		concurrentRequests := 100
		errChan := make(chan error, concurrentRequests)
		var wg sync.WaitGroup

		for i := 0; i < concurrentRequests; i++ {
			wg.Add(1)
			go func(reqNum int) {
				defer wg.Done()
				qsp := map[string]string{
					"url": fmt.Sprintf("https://example.com/image%d.jpg", reqNum),
				}

				request := events.APIGatewayProxyRequest{
					QueryStringParameters: qsp,
				}

				_, err := d.Handler(ctx, request)
				if err != nil {
					errChan <- fmt.Errorf("request %d failed: %v", reqNum, err)
				}
			}(i)
		}

		wg.Wait()
		close(errChan)

		// Check for any errors during concurrent execution
		var errors []error
		for err := range errChan {
			errors = append(errors, err)
		}

		if len(errors) > 0 {
			t.Errorf("Load test failed with %d errors: %v", len(errors), errors)
		}
	})

	t.Run("Successful Request", func(t *testing.T) {
		mpo := mockedPutOjbect {
			Response: s3.PutObjectOutput{},
		}

		mpi := mockedPutItem {
			Response: dynamodb.PutItemOutput{},
		}

		d := Dependency{
			DepS3: mpo,
			DepDynamoDB: mpi,
		}

		ctx := context.Background()
		lc := new(lambdacontext.LambdaContext)
		lc.InvokedFunctionArn = "arn:aws:lambda:region:123456789000:function:functionName"
		ctx = lambdacontext.NewContext(ctx, lc)

		qsp := map[string]string{}
		qsp["url"] = "https://cdn.britannica.com/05/30105-004-644BE36D.jpg"

		request := events.APIGatewayProxyRequest{
			QueryStringParameters: qsp,
		}

		_, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("TestHandler failed with %s", err.Error()))
		}
	})
}
