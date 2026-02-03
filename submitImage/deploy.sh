#!/bin/bash

# Deployment script for Mobile User Authentication System
set -e

# Configuration
STACK_NAME="mobile-auth-system"
ENVIRONMENT="dev"
REGION="us-east-1"
S3_BUCKET="your-deployment-bucket"  # Change this to your deployment bucket

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists aws; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    if ! command_exists go; then
        print_error "Go is not installed. Please install it first."
        exit 1
    fi
    
    if ! command_exists sam; then
        print_warning "SAM CLI is not installed. Using CloudFormation instead."
        USE_SAM=false
    else
        USE_SAM=true
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        print_error "AWS credentials not configured. Please run 'aws configure'."
        exit 1
    fi
    
    print_status "Prerequisites check passed!"
}

# Generate secure secrets
generate_secrets() {
    print_status "Generating secure secrets..."
    
    # Generate JWT secret (64 characters)
    JWT_SECRET=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
    
    # Generate encryption key (32 characters for AES-256)
    ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    
    print_status "Secrets generated successfully!"
}

# Build the Go application
build_application() {
    print_status "Building Go application..."
    
    # Clean previous builds
    rm -f main main.zip
    
    # Build for Linux (Lambda runtime)
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go
    
    # Create deployment package
    zip main.zip main
    
    print_status "Application built successfully!"
}

# Deploy using SAM
deploy_with_sam() {
    print_status "Deploying with SAM..."
    
    sam build --template-file template-auth.yml
    
    sam deploy \
        --template-file .aws-sam/build/template.yaml \
        --stack-name "$STACK_NAME" \
        --capabilities CAPABILITY_IAM \
        --parameter-overrides \
            Environment="$ENVIRONMENT" \
            JWTSecret="$JWT_SECRET" \
            EncryptionKey="$ENCRYPTION_KEY" \
        --s3-bucket "$S3_BUCKET" \
        --region "$REGION" \
        --confirm-changeset
}

# Deploy using CloudFormation
deploy_with_cloudformation() {
    print_status "Deploying with CloudFormation..."
    
    # Upload deployment package to S3
    aws s3 cp main.zip "s3://$S3_BUCKET/mobile-auth/main.zip" --region "$REGION"
    
    # Update template to use S3 location
    sed "s|CodeUri: \.|CodeUri: s3://$S3_BUCKET/mobile-auth/main.zip|g" template-auth.yml > template-auth-deploy.yml
    
    # Deploy stack
    aws cloudformation deploy \
        --template-file template-auth-deploy.yml \
        --stack-name "$STACK_NAME" \
        --capabilities CAPABILITY_IAM \
        --parameter-overrides \
            Environment="$ENVIRONMENT" \
            JWTSecret="$JWT_SECRET" \
            EncryptionKey="$ENCRYPTION_KEY" \
        --region "$REGION"
    
    # Clean up temporary file
    rm -f template-auth-deploy.yml
}

# Get stack outputs
get_outputs() {
    print_status "Getting stack outputs..."
    
    API_ENDPOINT=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`AuthAPIEndpoint`].OutputValue' \
        --output text)
    
    FUNCTION_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`AuthFunctionArn`].OutputValue' \
        --output text)
    
    echo ""
    print_status "Deployment completed successfully!"
    echo ""
    echo "API Endpoint: $API_ENDPOINT"
    echo "Function ARN: $FUNCTION_ARN"
    echo ""
    echo "Test the API:"
    echo "curl -X POST $API_ENDPOINT/auth/register \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '{\"email\":\"test@example.com\",\"password\":\"TestPass123!\",\"firstName\":\"Test\",\"lastName\":\"User\"}'"
    echo ""
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    if go test ./auth/... -v; then
        print_status "All tests passed!"
    else
        print_error "Some tests failed. Please fix them before deploying."
        exit 1
    fi
}

# Main deployment function
main() {
    echo "Mobile User Authentication System Deployment"
    echo "==========================================="
    echo ""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --stack-name)
                STACK_NAME="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --s3-bucket)
                S3_BUCKET="$2"
                shift 2
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --stack-name NAME     CloudFormation stack name (default: mobile-auth-system)"
                echo "  --environment ENV     Environment name (default: dev)"
                echo "  --region REGION       AWS region (default: us-east-1)"
                echo "  --s3-bucket BUCKET    S3 bucket for deployment artifacts"
                echo "  --skip-tests          Skip running tests"
                echo "  --help                Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate required parameters
    if [ -z "$S3_BUCKET" ]; then
        print_error "S3 bucket is required. Use --s3-bucket option or update the script."
        exit 1
    fi
    
    check_prerequisites
    
    if [ "$SKIP_TESTS" != "true" ]; then
        run_tests
    fi
    
    generate_secrets
    build_application
    
    if [ "$USE_SAM" = "true" ]; then
        deploy_with_sam
    else
        deploy_with_cloudformation
    fi
    
    get_outputs
    
    # Clean up
    rm -f main main.zip
    
    print_status "Deployment script completed!"
}

# Run main function
main "$@"