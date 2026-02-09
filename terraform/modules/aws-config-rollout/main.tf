variable "config_bucket_name" {
  description = "Central S3 bucket for AWS Config"
  type        = string
}

variable "ou_ids" {
  description = "List of OU IDs for governed accounts"
  type        = list(string)
}

variable "regions" {
  description = "Regions where AWS Config should be enabled"
  type        = list(string)
  default     = ["us-east-1", "ca-central-1"]
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "name_suffix" {
  description = "Suffix to append to StackSet names for uniqueness"
  type        = string
  default     = ""
}

# StackSet for IAM Role (deployed once per account, not per region)
resource "aws_cloudformation_stack_set" "aws_config_iam_role" {
  name             = var.name_suffix != "" ? "aws-config-iam-role-${var.name_suffix}" : "aws-config-iam-role"
  permission_model = "SERVICE_MANAGED"

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  capabilities = ["CAPABILITY_NAMED_IAM"]

  template_body = file("${path.root}/../cloudformation-templates/aws-config-iam-role.yaml")

  parameters = {
    ConfigBucketName = var.config_bucket_name
  }

  tags = var.tags
}

resource "aws_cloudformation_stack_set_instance" "aws_config_iam_role" {
  stack_set_name = aws_cloudformation_stack_set.aws_config_iam_role.name

  deployment_targets {
    organizational_unit_ids = var.ou_ids
  }

  # IAM is global, only deploy to one region
  region = "us-east-1"
}

# StackSet for Config Recorder and Delivery Channel (per region)
resource "aws_cloudformation_stack_set" "aws_config_baseline" {
  name             = var.name_suffix != "" ? "aws-config-baseline-${var.name_suffix}" : "aws-config-baseline"
  permission_model = "SERVICE_MANAGED"

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  template_body = file("${path.root}/../cloudformation-templates/aws-config-baseline.yaml")

  parameters = {
    ConfigBucketName = var.config_bucket_name
  }

  tags = var.tags
}

resource "aws_cloudformation_stack_set_instance" "aws_config_baseline" {
  for_each       = toset(var.regions)
  stack_set_name = aws_cloudformation_stack_set.aws_config_baseline.name

  deployment_targets {
    organizational_unit_ids = var.ou_ids
  }

  region = each.value

  # Wait for IAM role to be created first
  depends_on = [aws_cloudformation_stack_set_instance.aws_config_iam_role]
}
