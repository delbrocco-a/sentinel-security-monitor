variable "aws_region" {
  description = "The AWS resource region"
  type        =  string
  default     = "eu-west-2"
} 

variable "app_name" {
  description = "Application name"
  type        =  string
  default     = "sentinel"
}

variable "container_port" {
  description = "The container's listener port"
  type        =  number
  default     =  8080
}