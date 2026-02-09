terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket   = "copperleaf-devops-terraform-state" ## Specify backend bucket via command-line param: -backend-config="bucket=copperleaf-devops-terraform-state-dev"
    key    = "copperleaf-tag-compliance-config-terraform"
    region = "us-east-1"
  }

  required_version = ">= 1.0.5"
}

provider "aws" {
  region = "ca-central-1" # management account region
}