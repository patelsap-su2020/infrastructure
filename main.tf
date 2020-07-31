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
  name        = "application_security grp"
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
    security_groups = ["${aws_security_group.loadbalacer_grp.id}"]
  }

  ingress {
    description = "Custom TCP Rule"
    from_port   = 8080
    to_port     = 8080
    protocol    = "TCP"
    security_groups = ["${aws_security_group.loadbalacer_grp.id}"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "TCP"
    security_groups = ["${aws_security_group.loadbalacer_grp.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  

  tags = {
    Name = "application_security grp"
  }
}

#load balacer security grp
resource "aws_security_group" "loadbalacer_grp" {
  name        = "load_security_grp"
  description = "my security grp"
  vpc_id      = "${aws_vpc.aws_demo.id}"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
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

  ingress {
    description = "Custom TCP Rule"
    from_port   = 8080
    to_port     = 8080
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
    Name = "load_security grp"
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
    Name = "database_security_grp"
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
  skip_final_snapshot = true
  storage_encrypted = true
  parameter_group_name = "${aws_db_parameter_group.parameter_group.name}"
  
}

# parameter group
resource "aws_db_parameter_group" "parameter_group" {
  name   = "rds-pg"
  family = "mysql5.7"

  parameter {
    name  = "performance_schema"
    value = "1"
    apply_method = "pending-reboot"
  }

}

#EC2
# resource "aws_instance" "web" {
#   ami           = "${var.ami}"
#   instance_type = "t2.micro"
#   subnet_id = "${aws_subnet.subnet-2.id}"
#   vpc_security_group_ids = ["${aws_security_group.security_grp.id}"]
#   iam_instance_profile   = "CodeDeployEC2ServiceRole"
#   key_name = "${var.key_name}"

#   root_block_device {
#     volume_size = 20
#     volume_type = "gp2"
#   }

#   user_data = "${data.template_file.data.rendered}"

#   tags = {
#     Name = "Demo Instance"
#   }
# }

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
  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
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

#codedeploy-Ec2-s3
resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name = "CodeDeploy-EC2-S3"
 
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:DeleteObject",
                "s3:GetBucketLocation",
                "s3:GetEncryptionConfiguration",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:GetObjectVersion",
                "autoscaling:PutLifecycleHook",
                "autoscaling:DeleteLifecycleHook",
                "autoscaling:RecordLifecycleActionHeartbeat",
                "autoscaling:CompleteLifecycleAction",
                "autoscaling:DescribeAutoscalingGroups",
                "autoscaling:PutInstanceInStandby",
                "autoscaling:PutInstanceInService",
                "ec2:Describe*"
            ],
            "Effect": "Allow",
            "Resource": [
              "arn:aws:s3:::codedeploy.sapnapatel1.me",
			        "arn:aws:s3:::codedeploy.sapnapatel1.me/*"
              ]
        }
    ]
}

  EOF
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
}





#s3 readpolicy
resource "aws_iam_policy" "policy" {
  name   = "WebAppS3"
  # role   = aws_iam_role.EC2Role.id
  policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetObject",
      "s3:GetObjectAcl",
      "s3:DeleteObject"
    ],
		"Resource": [
			"arn:aws:s3:::webapp.sapna.patel",
			"arn:aws:s3:::webapp.sapna.patel/*"
		]
	}]
}
EOF

}

resource "aws_iam_role_policy_attachment" "attach-policy" {
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
  policy_arn = "${aws_iam_policy.policy.arn}"
}

resource "aws_iam_instance_profile" "EC2Profile" {
  name = "EC2-CSYE6225"
  role = "${aws_iam_role.EC2Role.name}"
}

#s3
resource "aws_s3_bucket" "b" {
  bucket        = "${var.bucket_name}"
  force_destroy = true
  acl           = "private"

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






#IAM Circleci

resource "aws_iam_user" "circleci" {
  name = "circleci"
  path = "/"

  tags = {
    tag-key = "circleci"
  }
}

resource "aws_iam_access_key" "lb" {
  user = "${aws_iam_user.circleci.name}"
}

resource "aws_iam_policy" "CircleCI-Upload-To-S3" {
  name = "CircleCI-Upload-To-S3"
 # user = "${aws_iam_user.circleci.name}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.sapnapatel1.me",
			          "arn:aws:s3:::codedeploy.sapnapatel1.me/*",
                "arn:aws:s3:::aws-codedeploy-us-east-1/*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "policy-attach_upload_s3" {
  user       = "circleci"
  policy_arn = "${aws_iam_policy.CircleCI-Upload-To-S3.arn}"
}


resource "aws_iam_policy" "CircleCI-Code-Deploy" {
  name = "CircleCI-Code-Deploy"
  # user = "${aws_iam_user.circleci.name}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
          "codedeploy:RegisterApplicationRevision",
          "codedeploy:GetApplication",
          "codedeploy:GetApplicationRevision",
          "codedeploy:GetDeploymentGroup"
      ],
      "Resource": [
        "arn:aws:codedeploy:us-east-1:478806934556:application:csye6225_webapp",
        "arn:aws:codedeploy:us-east-1:478806934556:deploymentgroup:csye6225_webapp/csye6225-webapp-deployment",
        "arn:aws:codedeploy:us-east-1:478806934556:application:lambda_webapp",
        "arn:aws:codedeploy:us-east-1:478806934556:deploymentgroup:lambda_webapp/lambda-webapp-deployment"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:us-east-1:478806934556:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:us-east-1:478806934556:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:us-east-1:478806934556:deploymentconfig:CodeDeployDefault.AllAtOnce",
        "arn:aws:codedeploy:us-east-1:478806934556:deploymentconfig:test-deployment-config"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "policy-attach_code_deplo" {
  user       = "circleci"
  policy_arn = "${aws_iam_policy.CircleCI-Code-Deploy.arn}"
}

resource "aws_iam_policy" "circleci-ec2-ami" {
  name = "circleci-ec2-ami"
  #user = "${aws_iam_user.circleci.name}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "policy-attach" {
  user       = "circleci"
  policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"
}



#IAM role CodeDeployEC2ServiceRole
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [
            "ec2.amazonaws.com",
            "lambda.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    name = "CodeDeployEC2ServiceRole"
  }
}

resource "aws_iam_policy" "CodeDeployEC2ServiceRolepolicy" {
  name   = "CodeDeployEC2ServiceRolepolicy"
  # role   = aws_iam_role.EC2Role.id
  policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetObject",
      "s3:GetObjectAcl",
      "s3:DeleteObject",
      "s3:GetBucketLocation",
      "s3:GetEncryptionConfiguration",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:GetObjectVersion",
      "autoscaling:PutLifecycleHook",
      "autoscaling:DeleteLifecycleHook",
      "autoscaling:RecordLifecycleActionHeartbeat",
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:DescribeAutoscalingGroups",
      "autoscaling:PutInstanceInStandby",
      "autoscaling:PutInstanceInService",
      "ec2:Describe*"
    ],
		"Resource": [
			"arn:aws:s3:::codedeploy.sapnapatel1.me",
			"arn:aws:s3:::codedeploy.sapnapatel1.me/*"
		]
	}]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach-policy-codedeplyeEC2" {
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
  policy_arn = "${aws_iam_policy.CodeDeployEC2ServiceRolepolicy.arn}"
}

resource "aws_iam_instance_profile" "CodeDeployeEC2Profile" {
  name = "CodeDeployEC2ServiceRole"
  role = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}



#codedeploye Application

# resource "aws_codedeploy_app" "csye6225_webapp" {
#   compute_platform = "Server"
#   name             = "csye6225_webapp"
# }


resource "aws_codedeploy_app" "csye6225_webapp" {
  compute_platform = "Server"
  name             = "csye6225_webapp"
}

#CodeDeployServiceRole
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service":  "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}

resource "aws_iam_role_policy_attachment" "AWSCodeDeployRoleForLambda" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}



resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225_webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
   deployment_config_name = "CodeDeployDefault.AllAtOnce"
   autoscaling_groups = ["${aws_autoscaling_group.bar.id}"]

  deployment_style {
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

   ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "Demo Instance"
    } 

    load_balancer_info {
    target_group_pair_info {
      prod_traffic_route {
        listener_arns = ["${aws_lb_listener.front_end.arn}"]
      }
    

      target_group {
        name = "${aws_lb_target_group.target_grp.name}"
      }
    }
  }
}

#s3 bucket for code deploy

resource "aws_s3_bucket" "s3" {
  bucket        = "codedeploy.sapnapatel1.me"
  force_destroy = true
  acl           = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
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
    Name        = "Code Deploy S3"
    Environment = "Dev"
  }
}


#cloudwatch agent policy

resource "aws_iam_role_policy_attachment" "CloudWatchAgentServerPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}

#auto-scalling

resource "aws_launch_configuration" "as_conf" {
  name   = "terraform-lc-example-"
  image_id      = "${var.ami}"
  instance_type = "t2.micro"
  iam_instance_profile   = "CodeDeployEC2ServiceRole"
  key_name = "${var.key_name}" 
  security_groups = ["${aws_security_group.security_grp.id}"]
  associate_public_ip_address = true
  user_data = "${data.template_file.data.rendered}"
 
}

resource "aws_autoscaling_group" "bar" {
  name                 = "bar"
  launch_configuration = "${aws_launch_configuration.as_conf.name}"
  desired_capacity     = 2
  min_size               = 2
  max_size               = 5
  default_cooldown     = 60
  health_check_type = "EC2"
  vpc_zone_identifier = ["${aws_subnet.subnet-2.id}","${aws_subnet.subnet-3.id}"]
  target_group_arns = ["${aws_lb_target_group.target_grp.arn}"]


  tag {
    key                 = "Name"
    value               = "Demo Instance"
    propagate_at_launch = true
  }

  }
#autoscaling policy up
  resource "aws_autoscaling_policy" "auto_policy" {
  name                   = "auto_policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.bar.name}"
  
}


resource "aws_cloudwatch_metric_alarm" "bat" {
  alarm_name          = "alarm_up"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "90"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.bar.name}"
  }

  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = ["${aws_autoscaling_policy.auto_policy.arn}"]
}

#autoscalling policy down
resource "aws_autoscaling_policy" "auto_policy_down" {
  name                   = "auto_policy_down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.bar.name}"
  
}


resource "aws_cloudwatch_metric_alarm" "down" {
  alarm_name          = "alarm_down"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.bar.name}"
  }

  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = ["${aws_autoscaling_policy.auto_policy_down.arn}"]
}



#load balancer
resource "aws_lb" "test" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["${aws_subnet.subnet-2.id}","${aws_subnet.subnet-3.id}","${aws_subnet.subnet.id}"]
  security_groups =  ["${aws_security_group.loadbalacer_grp.id}"]
  enable_deletion_protection = false
  
  access_logs {
    bucket  = "${var.bucket_name}"
  }

}

resource "aws_lb_target_group" "target_grp" {
  name        = "target-grp"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = "${aws_vpc.aws_demo.id}"
 
   stickiness {
     type = "lb_cookie"
     enabled = true
 }
}



# resource "aws_lb_target_group_attachment" "target_grp_attachment" {
#   target_group_arn = "${aws_lb_target_group.target_grp.arn}"
#   target_id        = "${aws_instance.web.id}"
# }


resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.test.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:478806934556:certificate/3d7f2fd4-f845-4b0f-a533-21e9de0d79bd"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.target_grp.arn}"
  }
}

resource "aws_lb_listener" "redirect_end" {
  load_balancer_arn = "${aws_lb.test.arn}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# route53


resource "aws_route53_record" "www" {
  zone_id = "Z07438731RE8566V59DFV"
  name    = ""
  type    = "A"

  alias {
    name                   = "${aws_lb.test.dns_name}"
    zone_id                = "${aws_lb.test.zone_id}"
    evaluate_target_health = true
  }
}


#lambda function policy
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.test_lambda.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.sns_topic.arn}"
  # qualifier     = "${aws_lambda_alias.test_alias.name}"
}


resource "aws_lambda_function" "test_lambda" {
  # s3_bucket = "${aws_s3_bucket.s3.bucket}"
  # s3_key = "webapp.zip"
  filename      = "lambda.zip"
  function_name = "lambda_function"
  role          = "${aws_iam_role.iam_for_lambda.arn}"
  handler       = "Handler.lambda_handler"
  runtime       = "python3.8"
  # source_code_hash = "${base64sha256(file("webapp(10).zip"))}
  # memory_size = 256
  # timeout= 180
  # reserved_concurrent_executions = 5

  environment {
    variables = {
      DOMAIN_NAME = "prod.sapnapatel.me"
      table = "${aws_dynamodb_table.dbTable.name}"
    }
  }

  tags= {
    Name = "Lambda Email"
  }

}



#lambda role policy

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}





# resource "aws_iam_policy" "policy_lambda" {
#   name   = "policy_lambda"
#   policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Action": "sts:AssumeRole",
#       "Principal": {
#         "Service": "lambda.amazonaws.com"
#       },
#       "Effect": "Allow",
#       "Sid": ""
#     }
#   ]
# }
# EOF
# }

# resource "aws_iam_role_policy_attachment" "lambda_logs" {
#   role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
#   policy_arn = "${aws_iam_policy.policy_lambda.arn}"
# }

#codedeploy for lambda

# resource "aws_codedeploy_app" "lambda_webapp" {
#   compute_platform = "Lambda"
#   name             = "lambda_webapp"
# }


# #codedeploy config for lambda
# resource "aws_codedeploy_deployment_config" "foo" {
#   deployment_config_name = "test-deployment-config"
#   compute_platform       = "Lambda"

#   traffic_routing_config {
#     type = "AllAtOnce"
#   }
# }


# resource "aws_codedeploy_deployment_group" "lambda-webapp-deployment" {
#   app_name              = "${aws_codedeploy_app.lambda_webapp.name}"
#   deployment_group_name = "lambda-webapp-deployment"
#   service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
#    deployment_config_name = "${aws_codedeploy_deployment_config.foo.id}"
#   #  autoscaling_groups = ["${aws_autoscaling_group.bar.id}"]

#   deployment_style {
#     deployment_option = "WITH_TRAFFIC_CONTROL"
#     deployment_type   = "BLUE_GREEN"
#   }

#   auto_rollback_configuration {
#     enabled = true
#     events  = ["DEPLOYMENT_STOP_ON_ALARM"]
#   }

  # #  ec2_tag_filter {
  # #     key   = "Name"
  # #     type  = "KEY_AND_VALUE"
  # #     value = "Demo Instance"
  # #   } 

  # #   load_balancer_info {
  # #   target_group_pair_info {
  # #     prod_traffic_route {
  # #       listener_arns = ["${aws_lb_listener.front_end.arn}"]
  # #     }
    

  # #     target_group {
  # #       name = "${aws_lb_target_group.target_grp.name}"
  # #     }
  #   }
  # }
# }


#sns-topic
resource "aws_sns_topic" "sns_topic" {
  name = "example-topic"
}

#SNS subscription
resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  topic_arn = "${aws_sns_topic.sns_topic.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.test_lambda.arn}"
}

#lambda policy attach to circleci

resource "aws_iam_policy" "update_policy" {
  name = "update_policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "lambda:UpdateFunctionCode",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "update_policy_attach" {
  user       = "circleci"
  policy_arn = "${aws_iam_policy.update_policy.arn}"
}

#dynamoDB access to lambda
resource "aws_iam_role_policy_attachment" "dynamoDbAccess" {
  policy_arn = "arn:aws:iam::478806934556:policy/dynamoDbAccess"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}

#AWSLambdaExcecution
resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRolepolicy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}

#SESLambdapolicy
resource "aws_iam_role_policy_attachment" "SESLambdapolicy" {
  policy_arn = "arn:aws:iam::478806934556:policy/SESLambdapolicy"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}

#codedeployEc2ServiceRole SNS policy
resource "aws_iam_role_policy_attachment" "SNSpolicy" {
  policy_arn = "arn:aws:iam::478806934556:policy/SNSpolicy"
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}
