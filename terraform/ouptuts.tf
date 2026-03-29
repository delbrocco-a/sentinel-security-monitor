output "ecs_repo_url" {
  description ="The URL of the ECR repository"
  value = aws_ecr_repository.sentinel.repository_url
}