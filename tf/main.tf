terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.67.0"
    }
  }

  required_version = ">= 1.4.2"
}

provider "aws" {
  default_tags {
    tags = local.tags
  }
}

data "aws_ec2_managed_prefix_list" "allow_list_ingress" {
    filter {
        name = "prefix-list-name"
        values = ["allow_list_ingress"]
    }
}

data "aws_availability_zones" "available" {}

locals {
  vpc_cidr         = "10.20.0.0/16"
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  public_subnet_cidrs = [
    for idx in range(length(local.azs)) :
    cidrsubnet(local.vpc_cidr, 8, idx + 1) 
  ]

  private_subnet_cidrs = [
    for idx in range(length(local.azs)) :
    cidrsubnet(local.vpc_cidr, 8, idx + 101) 
  ]

  tags = {
    Service = "ecr-private-multi-account"
  }
  
  ami_id = "ami-03598bf9d15814511"
}

### VPC  #######################################################
resource "aws_vpc" "vpc" {
  cidr_block           = local.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "${var.pj_name}_vpc"
  }
}

resource "aws_subnet" "private_subnet" {
  count = 1
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = local.private_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  tags = {
    Name = "${var.pj_name}_private_subnet"
  }
}

resource "aws_route_table" "private_rt" {
    vpc_id = aws_vpc.vpc.id
    tags = {
    Name = "${var.pj_name}_demo_private_rt"
  }
}

resource "aws_route_table_association" "private_assoc" {
  count = length(aws_subnet.private_subnet)

  route_table_id = aws_route_table.private_rt.id
  subnet_id      = aws_subnet.private_subnet[count.index].id
}

### SecurityGroup  #######################################################
resource "aws_security_group" "sg_vpc_endpoint" {
  name = "sg_vpc_endpoint"
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.pj_name}_sg_vpc_endpoint"
  }
}

resource "aws_security_group" "sg_ec2" {
  name = "sg_ec2"
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.pj_name}_sg_ec2"
  }
}

resource "aws_vpc_security_group_ingress_rule" "sg_vpc_endpoint_ingress" {
  security_group_id = aws_security_group.sg_vpc_endpoint.id
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
  referenced_security_group_id = aws_security_group.sg_ec2.id
}

resource "aws_vpc_security_group_egress_rule" "sg_vpc_endpoint_egress" {
  security_group_id = aws_security_group.sg_vpc_endpoint.id
  from_port = 0
  to_port = 65335
  ip_protocol = "tcp"
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "sg_ec2_egress" {
  security_group_id = aws_security_group.sg_ec2.id
  from_port = 0
  to_port = 65335
  ip_protocol = "tcp"
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ec2_ingress" {
  security_group_id = aws_security_group.sg_ec2.id
  from_port = 443
  to_port = 443
  ip_protocol = "tcp"
  referenced_security_group_id = aws_security_group.sg_vpc_endpoint.id
}

### Endpoint  #######################################################
resource "aws_vpc_endpoint" "s3" {
  vpc_id = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.region}.s3"
  route_table_ids = [aws_route_table.private_rt.id]
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    aws_subnet.private_subnet[0].id
  ]
  security_group_ids = [aws_security_group.sg_vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    aws_subnet.private_subnet[0].id
  ]
  security_group_ids = [aws_security_group.sg_vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    aws_subnet.private_subnet[0].id
  ]
  security_group_ids = [aws_security_group.sg_vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.region}.ecr.dkr"
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    aws_subnet.private_subnet[0].id
  ]
  security_group_ids = [aws_security_group.sg_vpc_endpoint.id]
}

# resource "aws_vpc_endpoint" "ecr_api" {
#   vpc_id = aws_vpc.vpc.id
#   service_name = "com.amazonaws.${var.region}.ecr.api"
#   vpc_endpoint_type = "Interface"
#   private_dns_enabled = true
#   subnet_ids = [
#     aws_subnet.private_subnet[0].id
#   ]
#   security_group_ids = [aws_security_group.sg_vpc_endpoint.id]
# }

### IAM  #######################################################
resource "aws_iam_role" "ec2_role" {
    name = "ec2_role"
    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    })
}

resource "aws_iam_policy" "ecr_access_policy" {
  name        = "ecr_access_policy"
  policy = file("ecr_access_policy.json")
}

resource "aws_iam_role_policy_attachment" "ec2_role_ssm_access_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_role_ecr_access_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ecr_access_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_role.name
}

### EC2  #######################################################
resource "aws_instance" "ecr_client" {
  ami                    = local.ami_id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_subnet[0].id
  vpc_security_group_ids = [aws_security_group.sg_ec2.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.id
  tags = {
    Name = "ecr_client"
  }
  user_data = file("../bin/bootstrap.sh")
}
