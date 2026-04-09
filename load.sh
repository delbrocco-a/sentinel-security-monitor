# Authenticate Docker to ECR
aws ecr get-login-password --region eu-west-2 | docker login --username AWS --password-stdin 320901122774.dkr.ecr.eu-west-2.amazonaws.com

# Build, tag and push
docker build -t sentinel ..
docker tag sentinel:latest 320901122774.dkr.ecr.eu-west-2.amazonaws.com/sentinel:latest
docker push 320901122774.dkr.ecr.eu-west-2.amazonaws.com/sentinel:latest

aws ecs update-service --cluster sentinel --service sentinel --force-new-deployment --region eu-west-2

sleep 30

aws ecs describe-tasks --cluster sentinel --tasks b9442f399b934f69823f030ce1c65668 --region eu-west-2 --query 'tasks[0].attachments[0].details'
aws ec2 describe-network-interfaces --network-interface-ids $ENI --region eu-west-2 --query 'NetworkInterfaces[0].Association.PublicIp' --output text