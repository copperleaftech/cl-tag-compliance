# Copperleaf Tag Compliance

Infrastructure-as-Code for enforcing tag compliance across the Copperleaf AWS Organization.

## What This Repo Does

This repository automates the deployment of **AWS Config** and **tag compliance rules** to all accounts within specified Organizational Units (OUs). It ensures that AWS resources are properly tagged for cost tracking, ownership, and governance.

### Enforced Tags

| Tag | Purpose |
|-----|---------|
| `CostCenter` | Cost allocation and chargeback |
| `Customer` | Customer or project identification |

## Repository Structure

```
cl-tag-compliance/
├── README.md                        # You are here
├── .gitignore                       # Git ignore rules
│
├── terraform/                       # Infrastructure deployment
│   ├── README.md                    # Detailed terraform usage guide
│   ├── main.tf                      # Root configuration (OU definitions)
│   ├── provider.tf                  # AWS provider and backend config
│   └── modules/
│       ├── aws-config-rollout/      # Enables AWS Config in accounts
│       └── tag-compliance-rule/     # Deploys tag compliance rules
│
├── cloudformation-templates/        # StackSet templates deployed to accounts
│   ├── aws-config-baseline.yaml     # Config recorder & delivery channel
│   ├── aws-config-iam-role.yaml     # IAM role for AWS Config
│   └── aws-config-required-tags.yaml# Config rules for required tags
│
└── scripts/                         # Utility scripts
```

## Quick Start

```bash
# 1. Navigate to terraform directory
cd terraform

# 2. Initialize terraform
terraform init

# 3. Plan changes (use appropriate AWS profile)
AWS_PROFILE=prod terraform plan

# 4. Apply changes
AWS_PROFILE=prod terraform apply
```

## How to Read This Repo

| If you want to... | Look at... |
|-------------------|------------|
| Understand terraform usage and architecture | `terraform/README.md` |
| See which OUs are covered | `terraform/main.tf` |
| Modify AWS provider or backend settings | `terraform/provider.tf` |
| Change how AWS Config is deployed | `terraform/modules/aws-config-rollout/` |
| Change tag compliance rules | `terraform/modules/tag-compliance-rule/` |
| Modify what gets deployed to member accounts | `cloudformation-templates/` |

## Covered OUs

| OU | Description |
|----|-------------|
| CloudOps | Core infrastructure accounts |
| SAP | SAP workload accounts |
| GeoSpatial | GeoSpatial application accounts |
| Support | Support and tooling accounts |

## How It Works

1. **Terraform** creates CloudFormation StackSets in the management account
2. **StackSets** automatically deploy stacks to all accounts in target OUs
3. **AWS Config** is enabled in each account/region
4. **Config Rules** evaluate resources for required tags
5. **Non-compliant resources** are flagged in AWS Config dashboard

## Related Resources

- [AWS Config Documentation](https://docs.aws.amazon.com/config/)
- [CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
- [AWS Organizations](https://docs.aws.amazon.com/organizations/)
