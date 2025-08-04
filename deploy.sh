#!/bin/bash

# SOC AI Agent Deployment Script
# This script deploys the SOC AI Agent to Google Cloud Platform

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
REGION="us-central1"
FUNCTION_NAME="soc-ai-agent"
PUBSUB_TOPIC="security-alerts"
NOTIFICATION_TOPIC="security-notifications"
SERVICE_ACCOUNT_NAME="soc-agent-sa"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if gcloud is installed
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if project ID is set
    if [ -z "$PROJECT_ID" ]; then
        print_error "GOOGLE_CLOUD_PROJECT environment variable is not set."
        echo "Please set it with: export GOOGLE_CLOUD_PROJECT=your-project-id"
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        print_error "No active gcloud authentication found."
        echo "Please authenticate with: gcloud auth login"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Enable required APIs
enable_apis() {
    print_status "Enabling required Google Cloud APIs..."
    
    local apis=(
        "cloudfunctions.googleapis.com"
        "pubsub.googleapis.com"
        "bigquery.googleapis.com"
        "aiplatform.googleapis.com"
        "logging.googleapis.com"
        "storage.googleapis.com"
        "iam.googleapis.com"
    )
    
    for api in "${apis[@]}"; do
        print_status "Enabling $api..."
        gcloud services enable "$api" --project="$PROJECT_ID"
    done
    
    print_success "APIs enabled successfully"
}

# Create service account
create_service_account() {
    print_status "Creating service account..."
    
    # Check if service account already exists
    if gcloud iam service-accounts describe "${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" --project="$PROJECT_ID" &>/dev/null; then
        print_warning "Service account already exists, skipping creation"
    else
        gcloud iam service-accounts create "$SERVICE_ACCOUNT_NAME" \
            --display-name="SOC AI Agent Service Account" \
            --description="Service account for SOC AI Agent operations" \
            --project="$PROJECT_ID"
    fi
    
    # Grant necessary roles
    local roles=(
        "roles/bigquery.dataEditor"
        "roles/bigquery.jobUser"
        "roles/pubsub.publisher"
        "roles/pubsub.subscriber"
        "roles/aiplatform.user"
        "roles/logging.logWriter"
        "roles/storage.objectViewer"
    )
    
    for role in "${roles[@]}"; do
        print_status "Granting role $role..."
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --role="$role"
    done
    
    print_success "Service account created and configured"
}

# Create Pub/Sub topics and subscriptions
create_pubsub_resources() {
    print_status "Creating Pub/Sub resources..."
    
    # Create security alerts topic
    if gcloud pubsub topics describe "$PUBSUB_TOPIC" --project="$PROJECT_ID" &>/dev/null; then
        print_warning "Topic $PUBSUB_TOPIC already exists"
    else
        gcloud pubsub topics create "$PUBSUB_TOPIC" --project="$PROJECT_ID"
        print_success "Created topic: $PUBSUB_TOPIC"
    fi
    
    # Create notifications topic
    if gcloud pubsub topics describe "$NOTIFICATION_TOPIC" --project="$PROJECT_ID" &>/dev/null; then
        print_warning "Topic $NOTIFICATION_TOPIC already exists"
    else
        gcloud pubsub topics create "$NOTIFICATION_TOPIC" --project="$PROJECT_ID"
        print_success "Created topic: $NOTIFICATION_TOPIC"
    fi
    
    print_success "Pub/Sub resources created"
}

# Create BigQuery dataset
create_bigquery_dataset() {
    print_status "Creating BigQuery dataset..."
    
    local dataset_id="soc_agent_data"
    
    if bq ls -d "$PROJECT_ID:$dataset_id" &>/dev/null; then
        print_warning "Dataset $dataset_id already exists"
    else
        bq mk --dataset \
            --description="SOC Agent incident data" \
            --location="US" \
            "$PROJECT_ID:$dataset_id"
        print_success "Created BigQuery dataset: $dataset_id"
    fi
}

# Deploy Cloud Function
deploy_function() {
    print_status "Deploying Cloud Function..."
    
    # Create a temporary deployment directory
    local deploy_dir="deploy_temp"
    mkdir -p "$deploy_dir"
    
    # Copy necessary files
    cp main.py "$deploy_dir/"
    cp requirements.txt "$deploy_dir/"
    cp -r soc_agent "$deploy_dir/"
    cp config.yaml "$deploy_dir/"
    
    # Create function configuration
    cat > "$deploy_dir/function-config.yaml" << EOF
functions:
  - name: $FUNCTION_NAME
    sourceArchiveUrl: gs://gcf-sources-${PROJECT_ID}/source.zip
    entryPoint: process_security_alert
    runtime: python311
    trigger:
      eventTrigger:
        eventType: google.pubsub.topic.publish
        resource: projects/$PROJECT_ID/topics/$PUBSUB_TOPIC
    environmentVariables:
      GOOGLE_CLOUD_PROJECT: $PROJECT_ID
    serviceAccountEmail: ${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
    timeout: 540s
    availableMemoryMb: 1024
EOF
    
    # Deploy the function
    cd "$deploy_dir"
    
    gcloud functions deploy "$FUNCTION_NAME" \
        --runtime=python311 \
        --trigger-topic="$PUBSUB_TOPIC" \
        --entry-point=process_security_alert \
        --source=. \
        --timeout=540 \
        --memory=1024MB \
        --service-account="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
        --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID" \
        --region="$REGION" \
        --project="$PROJECT_ID"
    
    cd ..
    rm -rf "$deploy_dir"
    
    print_success "Cloud Function deployed successfully"
}

# Deploy HTTP endpoint for manual testing
deploy_http_endpoint() {
    print_status "Deploying HTTP endpoint for manual testing..."
    
    local http_function_name="soc-agent-manual"
    local deploy_dir="deploy_http_temp"
    mkdir -p "$deploy_dir"
    
    # Copy necessary files
    cp main.py "$deploy_dir/"
    cp requirements.txt "$deploy_dir/"
    cp -r soc_agent "$deploy_dir/"
    cp config.yaml "$deploy_dir/"
    
    cd "$deploy_dir"
    
    gcloud functions deploy "$http_function_name" \
        --runtime=python311 \
        --trigger-http \
        --entry-point=manual_trigger \
        --source=. \
        --timeout=540 \
        --memory=1024MB \
        --service-account="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
        --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --allow-unauthenticated
    
    cd ..
    rm -rf "$deploy_dir"
    
    print_success "HTTP endpoint deployed successfully"
    
    # Get the HTTP trigger URL
    local http_url=$(gcloud functions describe "$http_function_name" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(httpsTrigger.url)")
    
    print_success "Manual testing endpoint: $http_url"
}

# Verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check function status
    local function_status=$(gcloud functions describe "$FUNCTION_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(status)")
    
    if [ "$function_status" = "ACTIVE" ]; then
        print_success "Cloud Function is active"
    else
        print_error "Cloud Function status: $function_status"
        return 1
    fi
    
    # Check Pub/Sub topic
    if gcloud pubsub topics describe "$PUBSUB_TOPIC" --project="$PROJECT_ID" &>/dev/null; then
        print_success "Pub/Sub topic is accessible"
    else
        print_error "Pub/Sub topic is not accessible"
        return 1
    fi
    
    print_success "Deployment verification completed"
}

# Print deployment summary
print_summary() {
    print_status "Deployment Summary"
    echo "=================================="
    echo "Project ID: $PROJECT_ID"
    echo "Region: $REGION"
    echo "Function Name: $FUNCTION_NAME"
    echo "Pub/Sub Topic: $PUBSUB_TOPIC"
    echo "Service Account: ${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    echo ""
    echo "Testing:"
    echo "1. Send a test message to Pub/Sub topic: $PUBSUB_TOPIC"
    echo "2. Use the manual HTTP endpoint for testing"
    echo "3. Check logs: gcloud functions logs read $FUNCTION_NAME --region=$REGION"
    echo ""
    echo "Configuration:"
    echo "- Update env.example with your API keys"
    echo "- Configure notification webhooks in config.yaml"
    echo "- Set up Chronicle Security Operations if available"
}

# Main deployment function
main() {
    print_status "Starting SOC AI Agent deployment..."
    
    check_prerequisites
    enable_apis
    create_service_account
    create_pubsub_resources
    create_bigquery_dataset
    deploy_function
    deploy_http_endpoint
    verify_deployment
    print_summary
    
    print_success "SOC AI Agent deployment completed successfully!"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--project PROJECT_ID] [--region REGION]"
            echo ""
            echo "Options:"
            echo "  --project    Google Cloud Project ID"
            echo "  --region     Deployment region (default: us-central1)"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main deployment
main 