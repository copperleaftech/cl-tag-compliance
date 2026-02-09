# Tag Compliance Terraform

Terraform configuration for deploying AWS Config and tag compliance rules across the Copperleaf AWS Organization using CloudFormation StackSets.

## Overview

This project enables AWS Config across multiple Organizational Units (OUs) and deploys tag compliance rules to enforce required resource tagging.

### Components

| Module | Description |
|--------|-------------|
| `aws-config-rollout` | Deploys AWS Config recorder, delivery channel, and IAM roles |
| `tag-compliance-rule` | Deploys AWS Config rules for required tag compliance |

### Target OUs

| OU | ID |
|----|-----|
| CloudOps | `ou-ncxy-k6jf5h7d` |
| SAP | `ou-ncxy-9vd1fpq6` |
| GeoSpatial | `ou-ncxy-v65280le` |
| Support | `ou-ncxy-jav04m19` |

### Regions

Deployed to 16 regions: `us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`, `ca-central-1`, `ap-southeast-5`, `ap-south-1`, `ap-northeast-1`, `ap-southeast-2`, `eu-central-1`, `eu-west-1`, `eu-north-1`, `eu-west-2`, `eu-west-3`, `me-central-1`, `me-south-1`

## Prerequisites

- Terraform >= 1.0.5
- AWS CLI configured with appropriate credentials
- Access to the AWS Organizations management account
- S3 bucket for Terraform state: `copperleaf-devops-terraform-state`

## Usage

### Initialize

```bash
cd terraform
terraform init
```

### Plan

```bash
# Production
AWS_PROFILE=prod terraform plan

# Development (with different backend)
AWS_PROFILE=dev terraform init -backend-config="bucket=copperleaf-devops-terraform-state-dev"
AWS_PROFILE=dev terraform plan
```

### Apply

```bash
AWS_PROFILE=prod terraform apply
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Management Account                         │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              CloudFormation StackSets                   ││
│  │  ┌─────────────────┐  ┌─────────────────────────────┐  ││
│  │  │ aws-config-     │  │ aws-config-required-tags    │  ││
│  │  │ iam-role        │  │ (Config Rules)              │  ││
│  │  │ aws-config-     │  │                             │  ││
│  │  │ baseline        │  │                             │  ││
│  │  └─────────────────┘  └─────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (Deploys to)
┌─────────────────────────────────────────────────────────────┐
│                    Member Accounts                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  CloudOps OU │  │   SAP OU     │  │ GeoSpatial   │  ...  │
│  │              │  │              │  │     OU       │       │
│  │ - Config     │  │ - Config     │  │ - Config     │       │
│  │ - IAM Role   │  │ - IAM Role   │  │ - IAM Role   │       │
│  │ - Tag Rules  │  │ - Tag Rules  │  │ - Tag Rules  │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (Delivers to)
┌─────────────────────────────────────────────────────────────┐
│              S3: cl-org-aws-config                           │
│              (Central Config Bucket)                         │
└─────────────────────────────────────────────────────────────┘
```

## Required Tags

The tag compliance rules enforce the following tags on resources:

- `CostCenter`
- `Customer`
- `Owner`

## File Structure

```
terraform/
├── main.tf                              # Root module - OU configurations
├── provider.tf                          # Provider and backend config
├── modules/
│   ├── aws-config-rollout/
│   │   └── main.tf                      # AWS Config baseline deployment
│   └── tag-compliance-rule/
│       └── main.tf                      # Tag compliance Config rules
cloudformation-templates/
├── aws-config-baseline.yaml             # Config recorder & delivery channel
├── aws-config-iam-role.yaml             # IAM role for Config
└── aws-config-required-tags.yaml        # Config rules for required tags
```

## Adding a New OU

To add tag compliance to a new OU:

```hcl
module "aws_config_rollout_<name>" {
  source             = "./modules/aws-config-rollout"
  config_bucket_name = "cl-org-aws-config"
  ou_ids             = ["ou-xxxx-xxxxxxxx"]
  regions            = local.regions
  tags               = local.common_tags
  name_suffix        = "<Name>"
}

module "tag_compliance_rule_<name>" {
  source      = "./modules/tag-compliance-rule"
  ou_ids      = ["ou-xxxx-xxxxxxxx"]
  regions     = local.regions
  tags        = local.common_tags
  name_suffix = "<Name>"
  depends_on  = [module.aws_config_rollout_<name>]
}
```
