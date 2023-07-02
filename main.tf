provider "aws" {
  region = "us-east-1"
}

#Retrieve the list of AZs in the current AWS region
data "aws_availability_zones" "available" {}
data "aws_region" "current" {}
data "aws_security_group" "test" {
  vpc_id = aws_vpc.vpc.id
  name   = "default"
}
data "aws_ami" "ubuntu_20_04" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  owners = ["099720109477"]
}

data "aws_ami" "red_hat" {
  most_recent = true

  filter {
    name   = "name"
    values = ["RHEL-9.0.0_HVM-20230127-x86_64-24-Hourly2-GP2"]
  }
  owners = ["309956199498"]
}

locals {
  teams       = "api_mgmt_dev"
  application = "corp_api"
  server_name = "ec2-${var.environment}-api-${var.variables_sub_az}"
}

locals {
  service_name = "Automation"
  app_team     = "Cloud Team"
  createdby    = "terraform"
}

locals {
  # Common tags to be assigned to all resources
  common_tags = {
    Name      = join("-", [local.application, data.aws_region.current.name, local.createdby])
    Owner     = lower(local.teams)
    App       = lower(local.application)
    Service   = lower(local.service_name)
    AppTeam   = lower(local.app_team)
    CreatedBy = lower(local.createdby)
  }
}

locals {
  ingress_rules = [{
    port        = 443
    description = "Port 443"
    },
    {
      port        = 80
      description = "Port 80"
    }
  ]
}

#Define the VPC
resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  tags = {
    Name        = var.vpc_name
    Environment = var.environment
    Terraform   = "true"
    region      = data.aws_region.current.name
  }
}

#Deploy the private subnets
resource "aws_subnet" "private_subnets" {
  for_each          = var.private_subnets
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, each.value)
  availability_zone = tolist(data.aws_availability_zones.available.names)[each.value]
  tags = {
    Name      = each.key
    Terraform = "true"
  }
}

#Deploy the public subnets
resource "aws_subnet" "public_subnets" {
  for_each                = var.public_subnets
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.value + 100)
  availability_zone       = tolist(data.aws_availability_zones.available.names)[each.value]
  map_public_ip_on_launch = true
  tags = {
    Name      = each.key
    Terraform = "true"
  }
}

#Create route tables for public and private subnets

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gateway.id
  }
  tags = {
    Name      = "demo_public_rtb"
    Terraform = "true"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }
  tags = {
    Name  = local.server_name
    Owner = local.teams
    App   = local.application
  }
}

#Create route table associations

resource "aws_route_table_association" "public" {
  depends_on     = [aws_subnet.public_subnets]
  route_table_id = aws_route_table.public_route_table.id
  for_each       = aws_subnet.public_subnets
  subnet_id      = each.value.id
}

resource "aws_route_table_association" "private" {
  depends_on     = [aws_subnet.private_subnets]
  route_table_id = aws_route_table.private_route_table.id
  for_each       = aws_subnet.private_subnets
  subnet_id      = each.value.id
}

#Create Internet Gateway
resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "demo_igw"
  }
}

#Create EIP for NAT Gateway
resource "aws_eip" "nat_gateway_eip" {
  domain      = vpc
  depends_on = [aws_internet_gateway.internet_gateway]
  tags = {
    Name = "demo_igw_eip"
  }
}

#Create NAT Gateway
resource "aws_nat_gateway" "nat_gateway" {
  depends_on    = [aws_subnet.public_subnets]
  allocation_id = aws_eip.nat_gateway_eip.id
  subnet_id     = aws_subnet.public_subnets["public_subnet_1"].id
  tags = {
    Name = "demo_nat_gateway"
  }
}

# Create s3 bucket and policy
resource "aws_s3_bucket" "my-new-s3-bucket" {
  bucket = "my-new-tf-test-bucket-s.g${random_string.randomness.id}"

  tags = {
    Name    = "My S3 Bucket"
    Purpose = "Intro to Resource Block Lab"
  }
}

resource "aws_s3_bucket_ownership_controls" "new_rules" {
  bucket = aws_s3_bucket.my-new-s3-bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "my-new-s3-bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.new_rules]
  
  bucket = aws_s3_bucket.my-new-s3-bucket.id
  acl    = "private"
}

resource "aws_instance" "ubuntu_server" {
  ami                         = data.aws_ami.ubuntu_20_04.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public_subnets["public_subnet_1"].id
  vpc_security_group_ids      = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.generated.key_name
  connection {
    user        = "ubuntu"
    private_key = tls_private_key.generated.private_key_pem
    host        = self.public_ip
  }
  tags = {
    "Name" = "Ubuntu EC2 Server"
  }

  lifecycle {
    ignore_changes = [security_groups]
  }
  #leave the first part of block unchanged and create our "local-exec" provisioner
  provisioner "local-exec" {
    command     = "chmod 600 ${local_file.private_key_pem.filename}"
  }
  provisioner "file" {
    source = "prometheus.service"
    destination = "/home/ubuntu/prometheus.service"
  }
  provisioner "file" {
    source = "prometheus.yml"
    destination = "/home/ubuntu/prometheus.yml"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo rm -rf /tmp",
      "sudo git clone https://github.com/hashicorp/demo-terraform-101 /tmp",
      "sudo sh /tmp/assets/setup-web.sh",
      "sudo groupadd -r prometheus",
      "sudo useradd -s /sbin/nologin -r -g prometheus prometheus",
      "sudo mkdir /var/lib/prometheus",
      "sudo mkdir -p /etc/prometheus/rules",
      "sudo mkdir -p /etc/prometheus/rules.s",
      "sudo mkdir -p /etc/prometheus/files_sd",
      "sudo mv /home/ubuntu/prometheus.yml /etc/prometheus/",
      "sudo chown -R prometheus:prometheus /etc/prometheus",
      "sudo chown -R prometheus:prometheus /etc/prometheus/*",
      "sudo chown -R prometheus:prometheus /var/lib/prometheus",
      "sudo chmod -R 775 /etc/prometheus",
      "sudo chmod -R 775 /etc/prometheus/*",
      "sudo wget https://github.com/prometheus/prometheus/releases/download/v2.45.0-rc.1/prometheus-2.45.0-rc.1.linux-amd64.tar.gz",
      "sudo gunzip prometheus-2.45.0-rc.1.linux-amd64.tar.gz",
      "sudo tar -xvf prometheus-2.45.0-rc.1.linux-amd64.tar && mv prometheus-2.45.0-rc.1.linux-amd64 prometheus-2.45", 
      "rm -rf prometheus-2.45.0-rc.1.linux-386.tar",
      "cd ~/prometheus-2.45",
      "sudo mv prometheus promtool /usr/local/bin",
#     "sudo mv prometheus.yml /etc/prometheus/prometheus.yml",
      "sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml",
      "sudo mv /home/ubuntu/prometheus.service /etc/systemd/system/",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable prometheus",
      "sudo systemctl start prometheus"
    ]
  }
}

resource "aws_instance" "red_hat_server" {
  ami                         = data.aws_ami.red_hat.id
  instance_type               = "t2.small"
  subnet_id                   = aws_subnet.public_subnets["public_subnet_1"].id
  vpc_security_group_ids      = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.generated.key_name
  connection {
    user        = "ec2-user"
    private_key = tls_private_key.generated.private_key_pem
    host        = self.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum remove podman -y",
      "sudo yum install yum-utils -y",
      "sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo",
      "sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y",
      "sudo usermod -G docker ec2-user",
      "sudo service docker start",
      "sudo chmod 777 /var/run/docker.sock",
      "sudo yum install zip -y",
      "sudo docker network create --driver=bridge --subnet=192.168.0.0/16  --ip-range=192.168.0.0/24 --gateway=192.168.0.1 192network",
      "sudo curl -SL https://github.com/docker/compose/releases/download/v2.16.0/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose",
      "sudo chmod +x /usr/local/bin/docker-compose",
      "curl --silent --location https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz | tar xz -C /tmp",
      "sudo mv /tmp/eksctl /usr/local/bin",
      "curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.25.7/2023-03-17/bin/linux/amd64/kubectl",
      "sudo chmod +x ./kubectl",
      "kubectl -n kube-system create serviceaccount tiller && kubectl create clusterrolebinding tiller --clusterrole cluster-admin --serviceaccount=kube-system:tiller",
      "mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin",
      "echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc",
      "curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip",
      "unzip awscliv2.zip",
      "sudo ./aws/install",
      "sudo yum install wget -y",
      "sudo yum install git -y",
      "curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3",
      "sudo chmod 700 get_helm.sh",
      "./get_helm.sh",
      "helm repo add bitnami https://charts.bitnami.com/bitnami",
      "helm repo add aws-ebs-csi-driver https://kubernetes-sigs.github.io/aws-ebs-csi-driver",
      "helm repo update",
      "sudo yum install java-11-openjdk -y",
      "echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-11.0.19.0.7-4.el9.x86_64' && echo 'export PATH=$PATH:$JAVA_HOME'",
      "sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat/jenkins.repo",
      "sudo rpm --import https://pkg.jenkins.io/redhat/jenkins.io-2023.key",
      "sudo yum install jenkins -y",
      "sudo usermod -G docker jenkins",
      "sudo systemctl enable jenkins && sudo systemctl start jenkins",
      "wget https://dlcdn.apache.org/maven/maven-3/3.9.1/binaries/apache-maven-3.9.1-bin.tar.gz",
      "sudo tar -xvzf apache-maven-3.9.1-bin.tar.gz",
      "rm apache-maven-3.9.1-bin.tar.gz",
      "cd ~",
      "mkdir chart && cd chart && mkdir chartsrepo",
      "helm create firstchart",
    ]
  }
  tags = {
    Name = "West Server"
  }
}

# Create security group 443 from internet

resource "aws_security_group" "my-new-security-group" {
  name        = "web_server_inbound"
  description = "Allow inbound traffic on tcp/443"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "Allow 443 from the Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name    = "web_server_inbound"
    Purpose = "Intro to Resource Blocks Lab"
  }
}

resource "random_string" "randomness" {
  length    = 4
  min_lower = 4
}

resource "aws_subnet" "variables-subnet" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.variables_sub_cidr
  availability_zone       = var.variables_sub_az
  map_public_ip_on_launch = var.variables_sub_auto_ip
  tags = {
    Name      = "sub-variables-${var.variables_sub_az}"
    Terraform = "true"
  }
}

resource "tls_private_key" "generated" {
  algorithm = "RSA"
}

resource "local_file" "private_key_pem" {
  content  = tls_private_key.generated.private_key_pem
  filename = "MyAWSKey.pem"
}

resource "aws_key_pair" "generated" {
  key_name   = "MyAWSKey"
  public_key = tls_private_key.generated.public_key_openssh

  lifecycle {
    ignore_changes = [key_name]
  }
}

resource "aws_security_group" "ingress-ssh" {
  name   = "allow-all-ssh"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  // Terraform removes default rule
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
  }
}
# Create security Group - Web Traffic

resource "aws_security_group" "vpc-web" {
  name        = "vpc-web-${terraform.workspace}"
  vpc_id      = aws_vpc.vpc.id
  description = "Web Traffic"
  ingress {
    description = "Allow Port 80"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 443"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 6443"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 9100"
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 2379"
    from_port   = 2379
    to_port     = 2379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 2380"
    from_port   = 2380
    to_port     = 2380
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 10250"
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 10251"
    from_port   = 10251
    to_port     = 10251
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 10252"
    from_port   = 10252
    to_port     = 10252
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow Port 10248"
    from_port   = 10248
    to_port     = 10248
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 8080"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 9090"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 4443"
    from_port   = 4443
    to_port     = 4443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 32750"
    from_port   = 32750
    to_port     = 32750
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow Port 179"
    from_port   = 179
    to_port     = 179
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Allow all IP and ports outbond"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

module "subnet_addrs" {
  source  = "hashicorp/subnets/cidr"
  version = "1.0.0"

  base_cidr_block = "10.0.0.0/22"
  networks = [
    {
      name     = "module_network_a"
      new_bits = 2
    },
    {
      name     = "module_network_b"
      new_bits = 2
    },
  ]
}

# Create aws_instance  web

/*module "server" {
  source          = "./modules/server"
  ami             = data.aws_ami.ubuntu_20_04.id
  subnet_id       = aws_subnet.public_subnets["public_subnet_3"].id
  security_groups = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id]
  key_name        = module.key-pair.key_name
  private_key     = module.key-pair.private_key_pem
  indentity       = "Ubuntu"
}
*/

/* module "server_subnet_1" {
  source          = "./modules/web-server"
  ami             = data.aws_ami.ubuntu_20_04.id
  subnet_id       = aws_subnet.public_subnets["public_subnet_1"].id
  security_groups = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id, aws_security_group.main.id]
  key_name        = aws_key_pair.generated.key_name
  private_key     = tls_private_key.generated.private_key_pem
  user            = "ubuntu"

}
*/
/*
module "autoscaling" {
  source = "github.com/terraform-aws-modules/terraform-aws-autoscaling"
  #Autoscaling group
  name                = "myasg"
  vpc_zone_identifier = [aws_subnet.private_subnets["private_subnet_1"].id, aws_subnet.private_subnets["private_subnet_3"].id]
  min_size            = 0
  max_size            = 1
  desired_capacity    = 1
  #Launch template
  create_launch_template = true

  image_id      = data.aws_ami.ubuntu_20_04.id
  instance_type = "t3.micro"

  tags = {
    Name = "Web EC2 Server 2"
  }
}
/*
/*
module "key-pair" {
  source  = "mitchellh/dynamic-keys/aws"
  version = "2.0.0"
  path    = "${path.root}/keys"
  name    = "MyAWSKey_2"
}
*/
resource "random_pet" "server" {
  length = 2
}

resource "aws_subnet" "list_subnet" {
  for_each          = var.env
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = each.value.ip
  availability_zone = each.value.az
}

resource "aws_security_group" "main" {
  name   = "core-sg"
  vpc_id = aws_vpc.vpc.id

  dynamic "ingress" {
    for_each = var.web_ingress

    content {
      description = ingress.value.description
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }
}

resource "aws_ecr_repository" "ecr_for_images" {
  name                 = "ecr_for_images"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
  tags = {
    "Ci_repository" = "true"
  }
}

resource "aws_eks_cluster" "first_cluster" {
  name     = var.eks_cluster
  role_arn = aws_iam_role.eks_first_cluster.arn
  vpc_config {
    subnet_ids = [aws_subnet.public_subnets["public_subnet_1"].id, aws_subnet.public_subnets["public_subnet_2"].id, aws_subnet.public_subnets["public_subnet_3"].id]
  }
  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.first_cluster-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.first_cluster-AmazonEKSVPCResourceController,
    aws_cloudwatch_log_group.eks_cloudwatch_log
  ]
  enabled_cluster_log_types = ["api", "audit"]
}

resource "aws_cloudwatch_log_group" "eks_cloudwatch_log" {
  # The log group name format is /aws/eks/<cluster-name>/cluster
  # Reference: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  name              = "/aws/eks/${var.eks_cluster}/cluster"
  retention_in_days = 7
}

data "tls_certificate" "eks_certificate" {
  url = aws_eks_cluster.first_cluster.identity[0].oidc[0].issuer
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_openid_connect_provider" "iam_openid_eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = data.tls_certificate.eks_certificate.certificates[*].sha1_fingerprint
  url             = data.tls_certificate.eks_certificate.url
}

data "aws_iam_policy_document" "eks_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.iam_openid_eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.iam_openid_eks.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "eks_first_cluster" {
  name               = "eks_first_cluster"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "first_cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_first_cluster.name
}

resource "aws_iam_role_policy_attachment" "first_cluster-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_first_cluster.name
}

resource "aws_iam_role" "assume_role_eks" {
  assume_role_policy = data.aws_iam_policy_document.eks_assume_role_policy.json
  name               = var.eks_cluster
}

resource "aws_iam_role" "node_group_role" {
  name = "eks-node-group"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "node_group_role-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group_role.name
}

resource "aws_iam_role_policy_attachment" "node_group_role-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group_role.name
}

resource "aws_iam_role_policy_attachment" "node_group_role-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group_role.name
}

resource "aws_iam_role_policy_attachment" "node_group_role-AmazonEBSCSIDriverPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.node_group_role.name
}

resource "aws_eks_node_group" "aws_eks_node_group" {
  cluster_name    = aws_eks_cluster.first_cluster.name
  node_group_name = "eks-node-group"
  node_role_arn   = aws_iam_role.node_group_role.arn
  subnet_ids      = [aws_subnet.public_subnets["public_subnet_1"].id, aws_subnet.public_subnets["public_subnet_2"].id]

  scaling_config {
    desired_size = 3
    max_size     = 3
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.node_group_role-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node_group_role-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node_group_role-AmazonEC2ContainerRegistryReadOnly,
  ]
}
/*
/*resource "aws_instance" "kube-master" {
  ami                         = data.aws_ami.red_hat.id
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.public_subnets["public_subnet_2"].id
  vpc_security_group_ids      = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.generated.key_name
  connection {
    user        = "ec2-user"
    private_key = tls_private_key.generated.private_key_pem
    host        = self.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum remove podman -y",
      "sudo yum install yum-utils -y",
      "sudo yum install zip -y",
      "sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo",
      "sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y",
      "sudo usermod -G docker ec2-user",
      "sudo service docker start",
      "curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.25.7/2023-03-17/bin/linux/amd64/kubectl",
      "sudo chmod +x ./kubectl",
      "mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin",
      "sudo setenforce 0",
      "sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/sysconfig/selinux",
      "sudo sed -i '/swap/d' /etc/fstab",
      "sudo swapoff -a",
    ]
  }
  tags = {
    Name = "Kube Master"
  }
}

resource "aws_instance" "kube-worker1" {
  ami                         = data.aws_ami.red_hat.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public_subnets["public_subnet_3"].id
  vpc_security_group_ids      = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.generated.key_name
  connection {
    user        = "ec2-user"
    private_key = tls_private_key.generated.private_key_pem
    host        = self.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum remove podman -y",
      "sudo yum install yum-utils -y",
      "sudo yum install zip -y",
      "sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo",
      "sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y",
      "sudo usermod -G docker ec2-user",
      "sudo service docker start",
      "curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.25.7/2023-03-17/bin/linux/amd64/kubectl",
      "sudo chmod +x ./kubectl",
      "mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin",
      "sudo setenforce 0",
      "sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/sysconfig/selinux",
      "sudo sed -i '/swap/d' /etc/fstab",
      "sudo swapoff -a",
    ]
  }
  tags = {
    Name = "Kube Worker1"
  }
}

resource "aws_instance" "kube-worker2" {
  ami                         = data.aws_ami.red_hat.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public_subnets["public_subnet_1"].id
  vpc_security_group_ids      = [data.aws_security_group.test.id, aws_security_group.ingress-ssh.id, aws_security_group.vpc-web.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.generated.key_name
  connection {
    user        = "ec2-user"
    private_key = tls_private_key.generated.private_key_pem
    host        = self.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum remove podman -y",
      "sudo yum install yum-utils -y",
      "sudo yum install zip -y",
      "sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo",
      "sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y",
      "sudo usermod -G docker ec2-user",
      "sudo service docker start",
      "curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.25.7/2023-03-17/bin/linux/amd64/kubectl",
      "sudo chmod +x ./kubectl",
      "mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin",
      "sudo setenforce 0",
      "sudo sed -i --follow-symlinks 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/sysconfig/selinux",
      "sudo sed -i '/swap/d' /etc/fstab",
      "sudo swapoff -a",
    ]
  }
  tags = {
    Name = "Kube Worker2"
  }
}
*/