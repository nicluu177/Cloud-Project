terraform {
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

# Run this "ssh-keygen -m PEM -t rsa -b 4096 -C "nicluu177@gmail.com" in terminal to generate pub/priv keys
# Once done, copy C:\Users\NL7\.ssh\id_rsa.pub to C:\Users\NL7\Cloud Project\Wazuh SIEM\wazuh_key.pub"
# And, copy C:\Users\NL7\.ssh\id_rsa to C:\Users\NL7\Cloud Project\Wazuh SIEM\wazuh_key"
# Create a key pair
resource "aws_key_pair" "wazuh_key" {
  key_name   = "wazuh-key"
  public_key = file("wazuh_key.pub")
}

######################################################################################################

# Create a default VPC
data "aws_vpc" "default_vpc" {
  default = true
}

# Create a default subnets
data "aws_subnets" "default_public_subnet" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default_vpc.id]
  }

  tags = {
    Name = "Wazuh-Default-VPC"
  }
}

# Create a custom subnet within the default VPC
resource "aws_subnet" "wazuh_subnet" {
  vpc_id            = data.aws_vpc.default_vpc.id
  cidr_block        = "172.31.255.0/24" # Replace with your desired CIDR block
  availability_zone = "us-east-1f"  # Replace with your desired Availability Zone

  tags = {
    Name = "Wazuh-Subnet"
  }
}

######################################################################################################

# Define a security group for the EC2 instances
resource "aws_security_group" "wazuh_sg" {
  name = "Wazuh-SG"
  vpc_id = data.aws_vpc.default_vpc.id #Associate the security group with the default VPC

  tags = {
    Name = "Wazuh-SG"
  }
}

# Create an inbound rule to allow SSH from anywhere to the Wazuh-server
resource "aws_security_group_rule" "wazuh_inbound_ssh_rule" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.wazuh_sg.id
}

# Create an inbound rule to allow HTTPS from anywhere to the Wazuh-server
resource "aws_security_group_rule" "wazuh_inbound_https_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.wazuh_sg.id
}

# Create inbound rules to allow communication within the VPC for the private instances
resource "aws_security_group_rule" "wazuh-private_inbound_rule" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = [data.aws_vpc.default_vpc.cidr_block]
  security_group_id = aws_security_group.wazuh_sg.id
}

# Create an outbound rule to allow all outbound traffic from the Wazuh-server
resource "aws_security_group_rule" "wazuh_outbound_rule" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1" # All protocols
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.wazuh_sg.id
}

######################################################################################################

# Define a security group for the private instances (Windows and Ubuntu)
resource "aws_security_group" "private_sg" {
  name   = "Private-SG"
  vpc_id = data.aws_vpc.default_vpc.id # Associate the security group with the default VPC

  tags = {
    Name = "Private-SG"
  }
}

# Create inbound rules to allow communication within the VPC for the private instances
resource "aws_security_group_rule" "private_inbound_rule" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = [data.aws_vpc.default_vpc.cidr_block]
  security_group_id = aws_security_group.private_sg.id
}

# Create an inbound rule to allow SSH from anywhere to the private instances
resource "aws_security_group_rule" "private_inbound_ssh_rule" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private_sg.id
}

# Create an inbound rule to allow RDP from anywhere to the private instances
resource "aws_security_group_rule" "private_inbound_rdp_rule" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private_sg.id
}

# Create an outbound rule to allow all outbound traffic from the private instances
resource "aws_security_group_rule" "outbound_rule" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1" # All protocols
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private_sg.id
}

######################################################################################################

#Create an EC2 instance (Amazon Linux 2)
resource "aws_instance" "Wazuh-server" {
  ami = "ami-0d94353f7bad10668" #Amazon Linux 2 AMI
  instance_type = "t2.medium"
  key_name      = aws_key_pair.wazuh_key.key_name # Associate the key pair
  subnet_id     = aws_subnet.wazuh_subnet.id      # Launch in the custom subnet
  vpc_security_group_ids = [aws_security_group.wazuh_sg.id] # Associate the private security group with the instance
  associate_public_ip_address = true # Assign a public IP address

  tags = {
    Name = "Wazuh-server"
  }
}

# Create an EC2 instance (Windows Server)
resource "aws_instance" "Windows-server" {
  ami           = "ami-0069eac59d05ae12b" # Microsoft Windows Server 2022 Base
  instance_type = "t2.micro"
  key_name      = aws_key_pair.wazuh_key.key_name # Associate the key pair
  subnet_id     = aws_subnet.wazuh_subnet.id      # Launch in the custom subnet
  vpc_security_group_ids = [aws_security_group.private_sg.id] # Associate the private security group with the instance
  associate_public_ip_address = true # Assign a public IP address

  tags = {
    Name = "Windows-Server"
  }
}

# Create an EC2 instance (Ubuntu Server)
resource "aws_instance" "Ubuntu-server" {
  ami           = "ami-0e001c9271cf7f3b9" # Ubuntu Server 22.04 LTS
  instance_type = "t2.micro"
  key_name      = aws_key_pair.wazuh_key.key_name # Associate the key pair
  subnet_id     = aws_subnet.wazuh_subnet.id      # Launch in the custom subnet
  vpc_security_group_ids = [aws_security_group.private_sg.id] # Associate the private security group with the instance
  associate_public_ip_address = true # Assign a public IP address

  tags = {
    Name = "Ubuntu-Server"
  }
}