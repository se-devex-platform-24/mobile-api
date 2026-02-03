#!/bin/bash

# Script to create DynamoDB tables for the mobile authentication system
# Make sure you have AWS CLI configured with appropriate permissions

set -e

echo "Creating DynamoDB tables for mobile authentication system..."

# Function to check if table exists
table_exists() {
    aws dynamodb describe-table --table-name "$1" >/dev/null 2>&1
}

# Function to wait for table to be active
wait_for_table() {
    echo "Waiting for table $1 to be active..."
    aws dynamodb wait table-exists --table-name "$1"
    echo "Table $1 is now active"
}

# Create Users table
if table_exists "Users"; then
    echo "Users table already exists"
else
    echo "Creating Users table..."
    aws dynamodb create-table \
        --table-name Users \
        --attribute-definitions \
            AttributeName=id,AttributeType=S \
            AttributeName=email,AttributeType=S \
        --key-schema \
            AttributeName=id,KeyType=HASH \
        --global-secondary-indexes \
            IndexName=email-index,KeySchema=[{AttributeName=email,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --billing-mode PROVISIONED
    
    wait_for_table "Users"
fi

# Create Sessions table
if table_exists "Sessions"; then
    echo "Sessions table already exists"
else
    echo "Creating Sessions table..."
    aws dynamodb create-table \
        --table-name Sessions \
        --attribute-definitions \
            AttributeName=id,AttributeType=S \
            AttributeName=user_id,AttributeType=S \
        --key-schema \
            AttributeName=id,KeyType=HASH \
        --global-secondary-indexes \
            IndexName=user-id-index,KeySchema=[{AttributeName=user_id,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --billing-mode PROVISIONED
    
    wait_for_table "Sessions"
fi

# Create PasswordResetTokens table
if table_exists "PasswordResetTokens"; then
    echo "PasswordResetTokens table already exists"
else
    echo "Creating PasswordResetTokens table..."
    aws dynamodb create-table \
        --table-name PasswordResetTokens \
        --attribute-definitions \
            AttributeName=id,AttributeType=S \
        --key-schema \
            AttributeName=id,KeyType=HASH \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --billing-mode PROVISIONED
    
    wait_for_table "PasswordResetTokens"
fi

# Create LoginAttempts table
if table_exists "LoginAttempts"; then
    echo "LoginAttempts table already exists"
else
    echo "Creating LoginAttempts table..."
    aws dynamodb create-table \
        --table-name LoginAttempts \
        --attribute-definitions \
            AttributeName=id,AttributeType=S \
            AttributeName=email,AttributeType=S \
            AttributeName=ip_address,AttributeType=S \
        --key-schema \
            AttributeName=id,KeyType=HASH \
        --global-secondary-indexes \
            IndexName=email-index,KeySchema=[{AttributeName=email,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
            IndexName=ip-address-index,KeySchema=[{AttributeName=ip_address,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --billing-mode PROVISIONED
    
    wait_for_table "LoginAttempts"
fi

# Create SecurityLogs table
if table_exists "SecurityLogs"; then
    echo "SecurityLogs table already exists"
else
    echo "Creating SecurityLogs table..."
    aws dynamodb create-table \
        --table-name SecurityLogs \
        --attribute-definitions \
            AttributeName=id,AttributeType=S \
        --key-schema \
            AttributeName=id,KeyType=HASH \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --billing-mode PROVISIONED
    
    wait_for_table "SecurityLogs"
fi

# Create ImageLabels table (if it doesn't exist from the original application)
if table_exists "ImageLabels"; then
    echo "ImageLabels table already exists"
else
    echo "Creating ImageLabels table..."
    aws dynamodb create-table \
        --table-name ImageLabels \
        --attribute-definitions \
            AttributeName=Id,AttributeType=S \
        --key-schema \
            AttributeName=Id,KeyType=HASH \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --billing-mode PROVISIONED
    
    wait_for_table "ImageLabels"
fi

echo "All tables created successfully!"
echo ""
echo "Table Summary:"
echo "- Users: Stores user account information"
echo "- Sessions: Stores user sessions and refresh tokens"
echo "- PasswordResetTokens: Stores password reset tokens"
echo "- LoginAttempts: Stores login attempts for security monitoring"
echo "- SecurityLogs: Stores security events for audit trail"
echo "- ImageLabels: Stores image metadata (existing functionality)"
echo ""
echo "Note: Tables are created with provisioned billing mode."
echo "Consider switching to on-demand billing for production workloads with unpredictable traffic."