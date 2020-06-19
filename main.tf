variable "region" {
  type= "string"
}

provider "aws" {
  region = "${var.region}"
}

variable "a_key" {
  type        = "string"
  description = "Enter Access Key:"
}
variable "s_key" {
  type        = "string"
  description = "Enter Secret Key:"
}
variable "key_name" {
  type        = "string"
  description = "Enter SSH Key Name:"
}

variable "bucket_name" {
  type        = "string"
  description = "Enter bucket_name Name:"
}

variable "ami" {
  type        = "string"
  description = "Enter ami:"
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
  availability_zone = "${var.region}a"
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet"
  }
}

resource "aws_subnet" "subnet-2" {
  cidr_block = "10.0.2.0/24"
  vpc_id     = "${aws_vpc.aws_demo.id}"
  availability_zone = "${var.region}b"
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet-2"
  }
}

resource "aws_subnet" "subnet-3" {
  cidr_block = "10.0.3.0/24"
  vpc_id     = "${aws_vpc.aws_demo.id}"
  availability_zone = "${var.region}c"
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

# security grp
resource "aws_security_group" "security_grp" {
  name        = "security_grp"
  description = "my security grp"
  vpc_id      = "${aws_vpc.aws_demo.id}"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Custom TCP Rule"
    from_port   = 8080
    to_port     = 8080
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "security grp"
  }
}



resource "aws_security_group" "database" {

  name        = "database"
  description = "my security grp for database"
  vpc_id      = "${aws_vpc.aws_demo.id}"

  ingress {
    description = "MYSQL"
    from_port   = 3306  
    to_port     = 3306
    protocol    = "TCP"
    security_groups = ["${aws_security_group.security_grp.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db_security_grp"
  }

}



#RDS 
resource "aws_db_subnet_group" "database_group" {
  name       = "database_group"
  subnet_ids = ["${aws_subnet.subnet-2.id}","${aws_subnet.subnet-3.id}"]

  tags = {
    Name = "My DB subnet group"
  }
}

resource "aws_db_instance" "RDS" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "csye6225"
  username             = "csye6225_su2020"
  password             = "SPvivid2020#"
  identifier           = "csye6225-su2020"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  db_subnet_group_name = "database_group"
}

#EC2
resource "aws_instance" "web" {
  ami           = "${var.ami}"
  instance_type = "t2.micro"
  subnet_id = "${aws_subnet.subnet-2.id}"
  vpc_security_group_ids = ["${aws_security_group.security_grp.id}"]
  iam_instance_profile   = "EC2-CSYE6225"
  key_name = "${var.key_name}"

  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }
  user_data = "${data.template_file.data.rendered}"
  tags = {
    Name = "Demo Instance"
  }
}

#DynamoDB
resource "aws_dynamodb_table" "dbTable" {
  name = "csye6225"
  hash_key = "id"
  billing_mode = "PROVISIONED"
  write_capacity = 5
  read_capacity = 5
  attribute {
    name = "id"
    type = "S"
  }

}

#IAM

resource "aws_iam_role" "EC2Role" {
  name = "EC2-CSYE6225"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "ec2.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    name = "EC2-CSYE6225"
  }
}

resource "aws_iam_policy" "policy" {
  name   = "WebAppS3"
  # role   = aws_iam_role.EC2Role.id
  policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "s3:*",
		"Resource": [
			"arn:aws:s3:::web-vanesa-krutarth",
			"arn:aws:s3:::web-vanesa-krutarth/*"
		]
	}]
}
  EOF

}

resource "aws_iam_role_policy_attachment" "attach-policy" {
  role       = "${aws_iam_role.EC2Role.name}"
  policy_arn = "${aws_iam_policy.policy.arn}"
}

resource "aws_iam_instance_profile" "EC2Profile" {
  name = "EC2-CSYE6225"
  role = "${aws_iam_role.EC2Role.name}"
}

#s3
resource "aws_s3_bucket" "b" {
  bucket        = "${var.bucket_name}"
  acl           = "public-read-write"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }

  lifecycle_rule {
    prefix  = "config/"
    enabled = true

    noncurrent_version_transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

  }
  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

data "template_file" "data" {
  template = "${file("install.tpl")}"

  vars={
    endpoint = "${aws_db_instance.RDS.endpoint}"
    bucket_name = "${aws_s3_bucket.b.bucket}"
    database_name = "${aws_db_instance.RDS.name}"
    username = "${aws_db_instance.RDS.username}"
    password = "${aws_db_instance.RDS.password}"
    a_key= "${var.a_key}"
    s_key= "${var.s_key}"
  }
}