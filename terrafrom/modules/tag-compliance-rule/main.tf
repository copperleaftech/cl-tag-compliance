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

resource "aws_cloudformation_stack_set" "aws_config_required_tags" {
  name             = var.name_suffix != "" ? "aws-config-required-tags-${var.name_suffix}" : "aws-config-required-tags"
  permission_model = "SERVICE_MANAGED"

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  template_body = file("${path.root}/../cloudformation-templates/aws-config-required-tags.yaml")

  tags = var.tags
}

resource "aws_cloudformation_stack_set_instance" "aws_config_tags" {
  for_each       = toset(var.regions)
  stack_set_name = aws_cloudformation_stack_set.aws_config_required_tags.name

  deployment_targets {
    organizational_unit_ids = var.ou_ids
  }

  region = each.value
}