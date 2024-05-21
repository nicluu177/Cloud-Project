#Create a Remote Backend using S3 Bucket
terraform {
  backend "s3" {
    bucket         = "devops-tf-lab-nl02148"
    key            = "web-app/terraform.tfstate"
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

#Create an EC2 instance 1
resource "aws_instance" "instance_1" {
  ami = "ami-0bb84b8ffd87024d8" #Ubuntu 20.04 LTS // us-east-1
  instance_type = "t2.micro"
  security_groups = [aws_security_group.instances.name]
  user_data = <<-EOF
    #!/bin/bash
    echo "Hello, World! from server 1" > index.html
    python3 -m http.server 8080 &
    EOF
}

#Create an EC2 instance 2
resource "aws_instance" "instance_2" {
  ami = "ami-0bb84b8ffd87024d8" #Ubuntu 20.04 LTS // us-east-1
  instance_type = "t2.micro"
  security_groups = [aws_security_group.instances.name]
  user_data = <<-EOF
    #!/bin/bash
    echo "Hello, World! from server 2" > index.html
    python3 -m http.server 8080 &
    EOF
}

# Create an S3 bucket for Terraform state / this already exists -> skip
# resource "aws_s3_bucket" "terraform_state" {
#   bucket = "devops-tf-lab-nl02148"
#   force_destroy = true
#   tags = {
#     Name = "Terraform state bucket"
#     Environment = "dev"
#   }
# }

# Enable versioning for the S3 bucket / this already exists -> skip
# resource "aws_s3_bucket_versioning" "terraform_state" {
#   bucket = aws_s3_bucket.terraform_state.id
#   versioning_configuration {
#     status = "Enabled"
#   }
# }

# Enable server-side encryption for the S3 bucket / this already exists -> skip
# resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
#   bucket = aws_s3_bucket.terraform_state.id

#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = "AES256"
#     }
#   }
# }

# Create an S3 bucket for storage
resource "aws_s3_bucket" "bucket" {
  bucket = "devops-tf-lab-nl02148-web-app"
  force_destroy = true
  tags = {
    Name = "Web-App Storage Bucket"
    Environment = "dev"
  }
}

# Enable versioning for the S3 bucket
resource "aws_s3_bucket_versioning" "bucket_versioning" {
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for the S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_crypto_conf" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Create a default VPC
data "aws_vpc" "default_vpc" {
  default = true
}

# Create a default subnets
data "aws_subnets" "default_subnet" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default_vpc.id]
  }
}

# Define a security group for the EC2 instances
resource "aws_security_group" "instances" {
  name = "instance-security-group"
}

# Allow HTTP access via port 8080 from anywhere to the EC2 instances
resource "aws_security_group_rule" "allow_http_inbound" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.instances.id
}

# Define a LB itself, what subnet & security group to use
resource "aws_lb" "load_balancer" {
    name = "web-app-lb"
    load_balancer_type = "application"
    subnets = data.aws_subnets.default_subnet.ids
    security_groups = [aws_security_group.alb.id]  
}

# Create a Load Balancer for HA
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.load_balancer.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "404: page not found"
      status_code = 404
    }
  }
}

# Create a Load Balancer's parameters
resource "aws_lb_target_group" "instances" {
    name = "example-target-group"
    port = 8080
    protocol = "HTTP"
    vpc_id = data.aws_vpc.default_vpc.id

    health_check {
      path = "/"
      protocol = "HTTP"
      matcher = "200"
      interval = 15
      timeout = 3
      healthy_threshold = 2
      unhealthy_threshold = 2
    }
}

# Attach the EC2 instances to the LB target group, so it knows where to direct traffic
resource "aws_lb_target_group_attachment" "instance_1" {
  target_group_arn = aws_lb_target_group.instances.arn
  target_id        = aws_instance.instance_1.id
  port             = 8080
}

resource "aws_lb_target_group_attachment" "instance_2" {
  target_group_arn = aws_lb_target_group.instances.arn
  target_id        = aws_instance.instance_2.id
  port             = 8080
}

# Set up a listener rule to direct traffic to the LB target group
resource "aws_lb_listener_rule" "instances" {
    listener_arn = aws_lb_listener.http.arn
    priority = 100

    condition {
      path_pattern {
        values = ["*"]
      }
    }

    action {
      type = "forward"
      target_group_arn = aws_lb_target_group.instances.arn
    }
}

# Define a security group for the Amazon Load Balancer
resource "aws_security_group" "alb" {
  name = "alb-security-group"
}

# Allow HTTP access from anywhere to the Amazon Load Balancer
resource "aws_security_group_rule" "allow_alb_http_inbound" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
}

# Block all outbound traffic from the Amazon Load Balancer
resource "aws_security_group_rule" "allow_alb_all_outbound" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb.id
}

# Create a Route53 zone for the domain
resource "aws_route53_zone" "primary" {
  name = "devops-tf-lab-nl02148.nl"
}

# Create a Route53 record within the Route53 zone
resource "aws_route53_record" "root" { 
    zone_id = aws_route53_zone.primary.zone_id
    name = "devops-tf-lab-nl02148.nl"
    type = "A"

    alias {
        name = aws_lb.load_balancer.dns_name
        zone_id = aws_lb.load_balancer.zone_id
        evaluate_target_health = true
    }
}

resource "aws_db_instance" "db_instance" {
    allocated_storage = 20
    auto_minor_version_upgrade = true
    storage_type = "standard"
    engine = "postgres"
    engine_version = "15.4"
    instance_class = "db.t3.micro"
    identifier = "mydb"
    username = "foo"
    password = "foobarbaz"
    skip_final_snapshot = true
}

# Create a DynamoDB table for Terraform state locking / this already exists -> skip
# resource "aws_dynamodb_table" "terraform_locks" {
#   name           = "terraform-state-locking"
#   billing_mode   = "PAY_PER_REQUEST"
#   hash_key       = "LockID"

#   attribute {
#     name = "LockID"
#     type = "S"
#   }
# }