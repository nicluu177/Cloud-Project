#Create a Remote Backend using S3 Bucket
terraform {
  backend "s3" {
    bucket         = "devops-tf-lab-nl02148"
    key            = "tf-infra/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-state-locking"
    encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

#Create an EC2 instance
resource "aws_instance" "test2" {
  ami = "ami-0bb84b8ffd87024d8"
  instance_type = "t2.micro"
}

# Create an S3 bucket for Terraform state
resource "aws_s3_bucket" "terraform_state" {
  bucket = "devops-tf-lab-nl02148"
  force_destroy = true
  tags = {
    Name = "Terraform state bucket"
    Environment = "dev"
  }
}

# Enable versioning for the S3 bucket
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for the S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Create a DynamoDB table for Terraform state locking
resource "aws_dynamodb_table" "terraform_locks" {
  name           = "terraform-state-locking"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}