# Configure the AWS Provider
provider "aws" { 
  region  = "us-east-1"
}

# Create a VPC
resource "aws_vpc" "aws_demo" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false
  tags = {
      Name = "aws_demo"
      Tag2 = "new tag"
  }
}

resource "aws_subnet" "subnet" {
  cidr_block = "10.0.1.0/24"
  vpc_id     = "${aws_vpc.aws_demo.id}"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet"
  }
}

resource "aws_subnet" "subnet-2" {
  cidr_block = "10.0.2.0/24"
  vpc_id     = "${aws_vpc.aws_demo.id}"
  availability_zone = "us-east-1b"
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet-2"
  }
}

resource "aws_subnet" "subnet-3" {
  cidr_block = "10.0.3.0/24"
  vpc_id     = "${aws_vpc.aws_demo.id}"
  availability_zone = "us-east-1c"
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet-3"
  }
}

resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = "${aws_vpc.aws_demo.id}"
  
  tags = {
    Name = "aws_internet_gateway"
  }
}

resource "aws_route_table" "route_table" {
  vpc_id = "${aws_vpc.aws_demo.id}"

#   route {
#     cidr_block = "10.0.1.0/24"
#     gateway_id = "${aws_internet_gateway.internet_gateway.id}"
#   }

#   route {
#     cidr_block = "10.0.2.0/24"
#     gateway_id = "${aws_internet_gateway.internet_gateway.id}"
#   }

#   route {
#     cidr_block = "10.0.3.0/24"
#     gateway_id = "${aws_internet_gateway.internet_gateway.id}"
#   }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.internet_gateway.id}"
  }

  tags = {
    Name = "route_table"
  }
}

resource "aws_route_table_association" "a" {
  
  route_table_id = "${aws_route_table.route_table.id}"
  subnet_id = "${aws_subnet.subnet.id}"
}

resource "aws_route_table_association" "b" {
  
  route_table_id = "${aws_route_table.route_table.id}"
  subnet_id = "${aws_subnet.subnet-2.id}"
}

resource "aws_route_table_association" "c" {
  
  route_table_id = "${aws_route_table.route_table.id}"
  subnet_id = "${aws_subnet.subnet-3.id}"
}
