provider "aws" {
  region = var.aws_region
}

# ECR repository to store Docker image
resource "aws_ecr_repository" "sentinel" {
  name         = var.app_name
  force_delete = true
}

# ECS cluster
resource "aws_ecs_cluster" "sentinel" {
  name = var.app_name
}

# Use default VPC and subnets for simplicity
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Security group - allow inbound on container port
resource "aws_security_group" "sentinel" {
  name   = var.app_name
  vpc_id = data.aws_vpc.default.id

  ingress {
    from_port   = var.container_port
    to_port     = var.container_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM role for ECS task execution
resource "aws_iam_role" "ecs_execution" {
  name = "${var.app_name}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "ecs_logs" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

# ECS task definition
resource "aws_ecs_task_definition" "sentinel" {
  family                   = var.app_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn

container_definitions = jsonencode([{
  name      = var.app_name
  image     = "${aws_ecr_repository.sentinel.repository_url}:latest"
  essential = true
  portMappings = [{
    containerPort = var.container_port
    protocol      = "tcp"
  }]
  logConfiguration = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = "/ecs/sentinel"
      "awslogs-region"        = var.aws_region
      "awslogs-stream-prefix" = "ecs"
      "awslogs-create-group"  = "true"
    }
  }
}])
}

# ECS service
resource "aws_ecs_service" "sentinel" {
  name            = var.app_name
  cluster         = aws_ecs_cluster.sentinel.id
  task_definition = aws_ecs_task_definition.sentinel.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.sentinel.id]
    assign_public_ip = true
  }
}