output "hello-world" {
  description = "Print a Hello World text output"
  value       = "Hello-Wolrd"
}

output "vpc_id" {
  description = "Output the ID for the primary VPC"
  value       = aws_vpc.vpc.id
}

output "public_url" {
  description = "Public URL for our web server"
  value       = "https://${aws_instance.ubuntu_server.public_ip}:8080/index.html"
}

output "public_dns_ubuntu_server" {
  value = aws_instance.ubuntu_server.public_dns
}

output "vpc_information" {
  description = "VPC information about Environment"
  value       = " Your ${aws_vpc.vpc.tags.Environment} VPC has an ID of ${aws_vpc.vpc.id}"
}
/*
output "public_ip" {
  value = module.server.public_ip
}

output "public_dns" {
  value = module.server.public_dns
}

output "public_url_2" {
  value = module.server.public_url
}

output "size_of_module_server_web" {
  value = module.server.size
}
*/
output "asg_group_size" {
  description = "The maximum size of the autoscaling group"
  value       = module.autoscaling.autoscaling_group_max_size
}

output "public_dns_red-hat" {
  value = aws_instance.red_hat_server.public_dns
}
/*
output "public_dns_win_server_os" {
  value = aws_instance.Win_Server_Os.public_dns
}
*/
output "subnet_addrs" {
  value = module.subnet_addrs.network_cidr_blocks
}

output "ecr_repository_url" {
  value = aws_ecr_repository.ecr_for_images.repository_url
}

/*
output "endpoint" {
  value = aws_eks_cluster.first_cluster.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.first_cluster.certificate_authority[0].data
}
*/
/*
output "public_dns_kube-master" {
  value = aws_instance.kube-master.public_dns
}

output "public_dns_kube-worker1" {
  value = aws_instance.kube-worker1.public_dns
}

output "public_dns_kube-worker2" {
  value = aws_instance.kube-worker2.public_dns
}
*/