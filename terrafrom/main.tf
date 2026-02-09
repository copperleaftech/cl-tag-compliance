locals {
  common_tags = {
    CostCenter = "General and Admin"
    Customer   = "Copperleaf"
    Owner      = "cloudops@copperleaf.com"
  }

  regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ap-southeast-5", "ap-south-1", "ap-northeast-1", "ap-southeast-2", "eu-central-1", "eu-west-1", "eu-north-1", "eu-west-2", "eu-west-3", "me-central-1", "me-south-1"]
}

# =====================================================
# CloudOps OU
# =====================================================
module "aws_config_rollout" {
  source             = "./modules/aws-config-rollout"
  config_bucket_name = "cl-org-aws-config"
  ou_ids             = ["ou-ncxy-k6jf5h7d"]
  regions            = local.regions
  tags               = local.common_tags
}

module "tag_compliance_rule" {
  source     = "./modules/tag-compliance-rule"
  ou_ids     = ["ou-ncxy-k6jf5h7d"]
  regions    = local.regions
  tags       = local.common_tags
  depends_on = [module.aws_config_rollout]
}

# =====================================================
# SAP OU
# =====================================================
module "aws_config_rollout_sap" {
  source             = "./modules/aws-config-rollout"
  config_bucket_name = "cl-org-aws-config"
  ou_ids             = ["ou-ncxy-9vd1fpq6"]
  regions            = local.regions
  tags               = local.common_tags
  name_suffix        = "sap"
}

module "tag_compliance_rule_sap" {
  source      = "./modules/tag-compliance-rule"
  ou_ids      = ["ou-ncxy-9vd1fpq6"]
  regions     = local.regions
  tags        = local.common_tags
  name_suffix = "sap"
  depends_on  = [module.aws_config_rollout_sap]
}

module "aws_config_rollout_geo_spatial" {
  source             = "./modules/aws-config-rollout"
  config_bucket_name = "cl-org-aws-config"
  ou_ids             = ["ou-ncxy-v65280le"]
  regions            = local.regions
  tags               = local.common_tags
  name_suffix        = "GeoSpatial"
}

module "tag_compliance_rule_geo_spatial" {
  source      = "./modules/tag-compliance-rule"
  ou_ids      = ["ou-ncxy-v65280le"]
  regions     = local.regions
  tags        = local.common_tags
  name_suffix = "GeoSpatial"
  depends_on  = [module.aws_config_rollout_geo_spatial]
}

module "aws_config_rollout_support" {
  source             = "./modules/aws-config-rollout"
  config_bucket_name = "cl-org-aws-config"
  ou_ids             = ["ou-ncxy-v65280le"]
  regions            = local.regions
  tags               = local.common_tags
  name_suffix        = "Support"
}

module "tag_compliance_rule_support" {
  source      = "./modules/tag-compliance-rule"
  ou_ids      = ["ou-ncxy-v65280le"]
  regions     = local.regions
  tags        = local.common_tags
  name_suffix = "Support"
  depends_on  = [module.aws_config_rollout_support]
}