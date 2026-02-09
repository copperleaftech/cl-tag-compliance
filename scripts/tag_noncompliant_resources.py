#!/usr/bin/env python3
"""
Script to tag non-compliant AWS resources identified by AWS Config aggregator.

This script:
1. Queries AWS Config aggregator (in root/management account) for resources 
   non-compliant with required-tags rule in a specified sub-account
2. Identifies which required tags (Customer, CostCenter) are missing
3. Assumes a role in the sub-account and applies the missing tags using 
   Resource Groups Tagging API

Cross-Account Setup:
- The AWS Config aggregator must be in the root/management account
- The script runs with credentials that have access to the root account (to query aggregator)
- To tag resources in sub-accounts, specify --role-name to assume in the target account
"""

import boto3
import logging
import argparse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from botocore.exceptions import ClientError

# Configure logging
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# Create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Console handler (file handler added later with account/region info)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(console_handler)


def get_log_filename(account_id: str, region: Optional[str] = None) -> str:
    """
    Generate log filename with timestamp, account ID, and region.
    
    Format: tag_noncompliant-YYYY-MM-DD_HHMMSS-<account_id>-<region|all>.log
    """
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    region_part = region if region else 'all'
    return f"tag_noncompliant-{timestamp}-{account_id}-{region_part}.log"


def setup_file_logging(log_filename: str):
    """Set up file handler for logging."""
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(file_handler)
    return log_filename


# Default required tags
DEFAULT_REQUIRED_TAGS = ['Customer', 'CostCenter']


@dataclass
class TaggingStats:
    """Statistics for the tagging operation."""
    total_noncompliant: int = 0
    processed: int = 0
    tagged: int = 0
    skipped: int = 0
    failed: int = 0
    unsupported: int = 0

    def log_summary(self):
        """Log the summary of the tagging operation."""
        logger.info("=" * 60)
        logger.info("TAGGING COMPLETE - SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total non-compliant resources found: {self.total_noncompliant}")
        logger.info(f"Resources processed: {self.processed}")
        logger.info(f"Resources successfully tagged: {self.tagged}")
        logger.info(f"Resources skipped (already compliant): {self.skipped}")
        logger.info(f"Resources failed: {self.failed}")
        logger.info(f"Resources unsupported for tagging: {self.unsupported}")


class ConfigAggregatorClient:
    """Client to query AWS Config aggregator for non-compliant resources."""

    def __init__(self, aggregator_name: str, region: Optional[str] = None):
        self.aggregator_name = aggregator_name
        self.region = region
        self.client = boto3.client('config', region_name=region)

    def get_noncompliant_resources(
        self,
        config_rule_name: str,
        account_id: str,
        aws_region: str
    ) -> list:
        """
        Get all non-compliant resources for a given Config rule from the aggregator.

        Args:
            config_rule_name: The name of the AWS Config rule (e.g., 'required-tags')
            account_id: AWS account ID (required)
            aws_region: AWS region (required)

        Returns:
            List of dictionaries containing resource information
        """
        noncompliant_resources = []

        try:
            logger.info(f"Querying account {account_id} in {aws_region}...")

            paginator = self.client.get_paginator(
                'get_aggregate_compliance_details_by_config_rule'
            )

            for page in paginator.paginate(
                ConfigurationAggregatorName=self.aggregator_name,
                ConfigRuleName=config_rule_name,
                ComplianceType='NON_COMPLIANT',
                AccountId=account_id,
                AwsRegion=aws_region
            ):
                for result in page.get('AggregateEvaluationResults', []):
                    resource_id = result.get('EvaluationResultIdentifier', {})
                    qualifier = resource_id.get('EvaluationResultQualifier', {})

                    resource_info = {
                        'resource_type': qualifier.get('ResourceType'),
                        'resource_id': qualifier.get('ResourceId'),
                        'account_id': account_id,
                        'region': aws_region,
                        'annotation': result.get('Annotation', ''),
                    }
                    noncompliant_resources.append(resource_info)

            logger.info(f"Found {len(noncompliant_resources)} non-compliant resources in {aws_region}")

        except ClientError as e:
            logger.error(f"Error querying Config aggregator: {e}")
            raise

        return noncompliant_resources

    def get_regions_for_account(self, account_id: str) -> list:
        """
        Discover all regions for a given account from the aggregator sources status.

        Uses describe_configuration_aggregator_sources_status to find all regions
        that are configured as sources in the aggregator for the specified account.

        Args:
            account_id: AWS account ID

        Returns:
            List of region names (e.g., ['us-east-1', 'us-west-2'])
        """
        regions = set()

        try:
            logger.info(f"Discovering regions for account {account_id} from aggregator sources...")

            paginator = self.client.get_paginator('describe_configuration_aggregator_sources_status')

            for page in paginator.paginate(
                ConfigurationAggregatorName=self.aggregator_name
            ):
                for source in page.get('AggregatedSourceStatusList', []):
                    source_id = source.get('SourceId')
                    source_region = source.get('AwsRegion')
                    
                    # Filter by the target account ID
                    if source_id == account_id and source_region:
                        regions.add(source_region)

            if not regions:
                logger.warning(
                    f"No regions found for account {account_id} in aggregator '{self.aggregator_name}'. "
                    "Verify the account is a source in the aggregator."
                )

            logger.info(f"Found {len(regions)} region(s) for account {account_id}: {sorted(regions)}")

        except ClientError as e:
            logger.error(f"Error discovering regions from aggregator sources: {e}")
            raise

        return sorted(regions)

    def list_aggregators(self) -> list:
        """List all Config aggregators in the account."""
        try:
            response = self.client.describe_configuration_aggregators()
            return [
                agg['ConfigurationAggregatorName']
                for agg in response.get('ConfigurationAggregators', [])
            ]
        except ClientError as e:
            logger.error(f"Error listing Config aggregators: {e}")
            return []


class ResourceTagger:
    """Tags AWS resources using the Resource Groups Tagging API."""

    # Resource types that don't support Resource Groups Tagging API
    UNSUPPORTED_TYPES = {
        'AWS::IAM::Role',
        'AWS::IAM::User',
        'AWS::IAM::Policy',
        'AWS::IAM::Group',
    }

    def __init__(
        self,
        region: Optional[str] = None,
        dry_run: bool = False,
        target_account_id: Optional[str] = None,
        role_name: Optional[str] = None,
    ):
        self.region = region
        self.dry_run = dry_run
        self.target_account_id = target_account_id
        self.role_name = role_name
        self._assumed_credentials = None

    def _assume_role(self, account_id: str) -> dict:
        """
        Assume a role in the target account to get credentials for tagging.
        
        Args:
            account_id: The AWS account ID to assume role in
            
        Returns:
            Dictionary with assumed role credentials
        """
        if not self.role_name:
            raise ValueError(
                "Role name is required for cross-account tagging. "
                "Specify --role-name to assume in the target account."
            )
        
        role_arn = f"arn:aws:iam::{account_id}:role/{self.role_name}"
        
        logger.info(f"Assuming role {role_arn} for cross-account tagging...")
        
        sts_client = boto3.client('sts')
        try:
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='NonCompliantResourceTagger',
                DurationSeconds=3600,  # 1 hour
            )
            credentials = response['Credentials']
            logger.info(f"Successfully assumed role in account {account_id}")
            return {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken'],
            }
        except ClientError as e:
            logger.error(f"Failed to assume role {role_arn}: {e}")
            raise

    def _get_tagging_client(self, region: str, account_id: Optional[str] = None):
        """
        Get a tagging client for the specified region.
        
        If account_id is provided and different from current account,
        assumes the configured role in the target account.
        """
        # If we need to tag in a different account, assume role
        if account_id and self.role_name:
            if self._assumed_credentials is None:
                self._assumed_credentials = self._assume_role(account_id)
            
            return boto3.client(
                'resourcegroupstaggingapi',
                region_name=region,
                **self._assumed_credentials
            )
        
        return boto3.client('resourcegroupstaggingapi', region_name=region)

    def _build_arn(self, resource_type: str, resource_id: str, account_id: str, region: str) -> Optional[str]:
        """
        Build an ARN from resource information.

        This is a best-effort attempt as ARN formats vary by service.
        """
        # Map Config resource types to ARN patterns
        arn_patterns = {
            'AWS::EC2::Instance': f'arn:aws:ec2:{region}:{account_id}:instance/{resource_id}',
            'AWS::EC2::Volume': f'arn:aws:ec2:{region}:{account_id}:volume/{resource_id}',
            'AWS::EC2::SecurityGroup': f'arn:aws:ec2:{region}:{account_id}:security-group/{resource_id}',
            'AWS::EC2::Subnet': f'arn:aws:ec2:{region}:{account_id}:subnet/{resource_id}',
            'AWS::EC2::VPC': f'arn:aws:ec2:{region}:{account_id}:vpc/{resource_id}',
            'AWS::EC2::NetworkInterface': f'arn:aws:ec2:{region}:{account_id}:network-interface/{resource_id}',
            'AWS::EC2::NatGateway': f'arn:aws:ec2:{region}:{account_id}:natgateway/{resource_id}',
            'AWS::EC2::EIP': f'arn:aws:ec2:{region}:{account_id}:elastic-ip/{resource_id}',
            'AWS::EC2::Snapshot': f'arn:aws:ec2:{region}:{account_id}:snapshot/{resource_id}',
            'AWS::EC2::Image': f'arn:aws:ec2:{region}:{account_id}:image/{resource_id}',
            'AWS::EC2::InternetGateway': f'arn:aws:ec2:{region}:{account_id}:internet-gateway/{resource_id}',
            'AWS::EC2::NetworkAcl': f'arn:aws:ec2:{region}:{account_id}:network-acl/{resource_id}',
            'AWS::EC2::RouteTable': f'arn:aws:ec2:{region}:{account_id}:route-table/{resource_id}',
            'AWS::RDS::DBInstance': f'arn:aws:rds:{region}:{account_id}:db:{resource_id}',
            'AWS::RDS::DBCluster': f'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}',
            'AWS::RDS::DBSnapshot': f'arn:aws:rds:{region}:{account_id}:snapshot:{resource_id}',
            'AWS::S3::Bucket': f'arn:aws:s3:::{resource_id}',
            'AWS::Lambda::Function': f'arn:aws:lambda:{region}:{account_id}:function:{resource_id}',
            'AWS::DynamoDB::Table': f'arn:aws:dynamodb:{region}:{account_id}:table/{resource_id}',
            'AWS::EFS::FileSystem': f'arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{resource_id}',
            'AWS::ELB::LoadBalancer': f'arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{resource_id}',
            'AWS::ElasticLoadBalancingV2::LoadBalancer': resource_id,  # resource_id is already the ARN
            'AWS::ElasticLoadBalancingV2::TargetGroup': resource_id,  # resource_id is already the ARN
            'AWS::SNS::Topic': f'arn:aws:sns:{region}:{account_id}:{resource_id}',
            'AWS::SQS::Queue': f'arn:aws:sqs:{region}:{account_id}:{resource_id}',
            'AWS::KMS::Key': f'arn:aws:kms:{region}:{account_id}:key/{resource_id}',
            'AWS::SecretsManager::Secret': f'arn:aws:secretsmanager:{region}:{account_id}:secret:{resource_id}',
            'AWS::ECR::Repository': f'arn:aws:ecr:{region}:{account_id}:repository/{resource_id}',
            'AWS::ECS::Cluster': f'arn:aws:ecs:{region}:{account_id}:cluster/{resource_id}',
            'AWS::ECS::Service': resource_id,  # resource_id is already the ARN
            'AWS::EKS::Cluster': f'arn:aws:eks:{region}:{account_id}:cluster/{resource_id}',
            'AWS::Redshift::Cluster': f'arn:aws:redshift:{region}:{account_id}:cluster:{resource_id}',
            'AWS::CloudWatch::Alarm': f'arn:aws:cloudwatch:{region}:{account_id}:alarm:{resource_id}',
            'AWS::Logs::LogGroup': f'arn:aws:logs:{region}:{account_id}:log-group:{resource_id}',
            'AWS::IAM::Role': f'arn:aws:iam::{account_id}:role/{resource_id}',
            'AWS::IAM::User': f'arn:aws:iam::{account_id}:user/{resource_id}',
            'AWS::IAM::Policy': f'arn:aws:iam::{account_id}:policy/{resource_id}',
            'AWS::Backup::BackupVault': f'arn:aws:backup:{region}:{account_id}:backup-vault:{resource_id}',
            'AWS::Backup::RecoveryPoint': resource_id,  # resource_id is already the ARN
            'AWS::FSx::FileSystem': f'arn:aws:fsx:{region}:{account_id}:file-system/{resource_id}',
            'AWS::Glue::Database': f'arn:aws:glue:{region}:{account_id}:database/{resource_id}',
            'AWS::Glue::Table': resource_id,  # complex ARN
            'AWS::Athena::WorkGroup': f'arn:aws:athena:{region}:{account_id}:workgroup/{resource_id}',
            'AWS::StepFunctions::StateMachine': f'arn:aws:states:{region}:{account_id}:stateMachine:{resource_id}',
            'AWS::CodeBuild::Project': f'arn:aws:codebuild:{region}:{account_id}:project/{resource_id}',
            'AWS::CodePipeline::Pipeline': f'arn:aws:codepipeline:{region}:{account_id}:{resource_id}',
            'AWS::QuickSight::Dashboard': f'arn:aws:quicksight:{region}:{account_id}:dashboard/{resource_id}',
            'AWS::QuickSight::DataSet': f'arn:aws:quicksight:{region}:{account_id}:dataset/{resource_id}',
            'AWS::QuickSight::DataSource': f'arn:aws:quicksight:{region}:{account_id}:datasource/{resource_id}',
            'AWS::QuickSight::Analysis': f'arn:aws:quicksight:{region}:{account_id}:analysis/{resource_id}',
            'AWS::QuickSight::Template': f'arn:aws:quicksight:{region}:{account_id}:template/{resource_id}',
            'AWS::QuickSight::Theme': f'arn:aws:quicksight:{region}:{account_id}:theme/{resource_id}',
        }

        # Check if resource_id is already an ARN
        if resource_id.startswith('arn:aws:'):
            return resource_id

        arn = arn_patterns.get(resource_type)
        if not arn:
            logger.warning(f"Unknown resource type for ARN building: {resource_type}")
            # Try a generic approach - this may not work for all resources
            return None

        return arn

    def get_existing_tags(self, arn: str, region: str, account_id: Optional[str] = None) -> dict:
        """Get existing tags on a resource."""
        try:
            client = self._get_tagging_client(region, account_id)
            response = client.get_resources(ResourceARNList=[arn])

            for resource in response.get('ResourceTagMappingList', []):
                if resource['ResourceARN'] == arn:
                    return {tag['Key']: tag['Value'] for tag in resource.get('Tags', [])}

            return {}

        except ClientError as e:
            logger.debug(f"Could not get tags for {arn}: {e}")
            return {}

    def tag_resource(self, arn: str, tags: dict, region: str, account_id: Optional[str] = None) -> bool:
        """
        Tag a resource with the provided tags.

        Args:
            arn: The resource ARN
            tags: Dictionary of tag key-value pairs
            region: AWS region
            account_id: AWS account ID (for cross-account tagging)

        Returns:
            True if tagging was successful, False otherwise
        """
        if not tags:
            return True

        try:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would tag {arn} with: {tags}")
                return True

            client = self._get_tagging_client(region, account_id)
            response = client.tag_resources(
                ResourceARNList=[arn],
                Tags=tags
            )

            # Check for failures
            failed = response.get('FailedResourcesMap', {})
            if arn in failed:
                error_info = failed[arn]
                logger.error(
                    f"Failed to tag {arn}: {error_info.get('ErrorCode')} - "
                    f"{error_info.get('ErrorMessage')}"
                )
                return False

            logger.info(f"Successfully tagged {arn} with {len(tags)} tag(s)")
            return True

        except ClientError as e:
            logger.error(f"Error tagging {arn}: {e}")
            return False


class NonCompliantResourceTagger:
    """Main class to orchestrate tagging of non-compliant resources."""

    def __init__(
        self,
        aggregator_name: str,
        config_rule_name: str,
        required_tags: dict,
        target_account: str,
        target_region: Optional[str] = None,
        aggregator_region: Optional[str] = None,
        role_name: Optional[str] = None,
        dry_run: bool = False,
    ):
        self.aggregator_name = aggregator_name
        self.config_rule_name = config_rule_name
        self.required_tags = required_tags  # {tag_key: tag_value}
        self.target_account = target_account
        self.target_region = target_region  # None means all regions
        self.aggregator_region = aggregator_region
        self.role_name = role_name
        self.dry_run = dry_run

        # Config client uses aggregator region (root account)
        self.config_client = ConfigAggregatorClient(aggregator_name, aggregator_region)
        # Tagger will assume role in target account if role_name is provided
        self.tagger = ResourceTagger(
            region=aggregator_region,
            dry_run=dry_run,
            target_account_id=target_account,
            role_name=role_name,
        )
        self.stats = TaggingStats()

    def process_resource(self, resource: dict):
        """Process a single non-compliant resource."""
        resource_type = resource['resource_type']
        resource_id = resource['resource_id']
        account_id = resource['account_id']
        resource_region = resource['region']

        self.stats.processed += 1

        # Check if resource type is supported
        if resource_type in ResourceTagger.UNSUPPORTED_TYPES:
            logger.warning(
                f"Skipping unsupported resource type: {resource_type} "
                f"(resource: {resource_id})"
            )
            self.stats.unsupported += 1
            return

        # Build ARN
        arn = self.tagger._build_arn(
            resource_type, resource_id, account_id, resource_region
        )
        if not arn:
            logger.warning(f"Could not build ARN for {resource_type}: {resource_id}")
            self.stats.failed += 1
            return

        logger.debug(f"Processing: {arn}")

        # Get existing tags (using assumed role for cross-account)
        existing_tags = self.tagger.get_existing_tags(arn, resource_region, account_id)

        # Determine which required tags are missing
        tags_to_apply = {}
        for tag_key, tag_value in self.required_tags.items():
            if tag_key not in existing_tags:
                tags_to_apply[tag_key] = tag_value
            else:
                logger.debug(f"Tag '{tag_key}' already exists on {arn}")

        if not tags_to_apply:
            logger.info(f"Resource {arn} already has all required tags")
            self.stats.skipped += 1
            return

        # Apply missing tags (using assumed role for cross-account)
        logger.info(f"Applying tags to {arn}: {tags_to_apply}")
        if self.tagger.tag_resource(arn, tags_to_apply, resource_region, account_id):
            self.stats.tagged += 1
        else:
            self.stats.failed += 1

    def run(self):
        """Main method to process all non-compliant resources."""
        logger.info("=" * 60)
        logger.info("NON-COMPLIANT RESOURCE TAGGING")
        logger.info("=" * 60)
        logger.info(f"Config Aggregator: {self.aggregator_name} (root account)")
        logger.info(f"Aggregator Region: {self.aggregator_region or 'default'}")
        logger.info(f"Config Rule: {self.config_rule_name}")
        logger.info(f"Target Sub-Account: {self.target_account}")
        logger.info(f"Target Region: {self.target_region or 'ALL REGIONS'}")
        if self.role_name:
            logger.info(f"Cross-Account Role: {self.role_name}")
        logger.info(f"Tags to apply: {self.required_tags}")
        if self.dry_run:
            logger.info("*** DRY RUN MODE - No changes will be made ***")
        logger.info("=" * 60)

        # Determine which regions to process
        if self.target_region:
            regions_to_process = [self.target_region]
        else:
            # Discover all regions for this account from the aggregator
            regions_to_process = self.config_client.get_regions_for_account(self.target_account)
            logger.info(f"Will process {len(regions_to_process)} region(s)")

        # Collect non-compliant resources from all regions
        all_noncompliant = []
        for region in regions_to_process:
            try:
                noncompliant = self.config_client.get_noncompliant_resources(
                    config_rule_name=self.config_rule_name,
                    account_id=self.target_account,
                    aws_region=region
                )
                all_noncompliant.extend(noncompliant)
            except ClientError as e:
                logger.warning(f"Could not query region {region}: {e}")
                continue

        self.stats.total_noncompliant = len(all_noncompliant)

        if not all_noncompliant:
            logger.info("No non-compliant resources found!")
            return

        logger.info(f"Total non-compliant resources across all regions: {len(all_noncompliant)}")

        # Process each resource
        for resource in all_noncompliant:
            try:
                self.process_resource(resource)
            except Exception as e:
                logger.error(f"Error processing resource {resource}: {e}")
                self.stats.failed += 1

        # Log summary
        self.stats.log_summary()


def main():
    parser = argparse.ArgumentParser(
        description='Tag non-compliant AWS resources from Config aggregator. '
                    'Queries Config aggregator in root/management account and tags '
                    'resources in the specified sub-account. Adds missing Customer '
                    'and CostCenter tags to resources identified as non-compliant.',
        epilog='Examples:\n'
               '  Single region: %(prog)s -a MyAggregator --account 123456789012 '
               '--target-region us-east-1 --customer ACME --cost-center CC-1234 --dry-run\n'
               '  All regions:   %(prog)s -a MyAggregator --account 123456789012 '
               '--customer ACME --cost-center CC-1234 --role-name OrganizationAccountAccessRole'
    )
    parser.add_argument(
        '--aggregator', '-a',
        required=True,
        help='Name of the AWS Config aggregator'
    )
    parser.add_argument(
        '--config-rule', '-c',
        default='required-tags',
        help='Name of the Config rule to check (default: required-tags)'
    )
    parser.add_argument(
        '--customer',
        required=True,
        help='Value for the Customer tag'
    )
    parser.add_argument(
        '--cost-center',
        required=True,
        help='Value for the CostCenter tag'
    )
    parser.add_argument(
        '--account', '-A',
        required=True,
        help='AWS sub-account ID to query for non-compliant resources (required). '
             'This is the member account whose resources need tagging.'
    )
    parser.add_argument(
        '--target-region', '-R',
        help='AWS region to query for non-compliant resources. '
             'If not specified, all regions found in the aggregator for the account will be processed.'
    )
    parser.add_argument(
        '--aggregator-region',
        help='AWS region where Config aggregator is located in root account (uses default if not specified)'
    )
    parser.add_argument(
        '--role-name',
        help='IAM role name to assume in the target sub-account for tagging resources. '
             'The role must exist in the sub-account and trust the root account.'
    )
    parser.add_argument(
        '--dry-run', '-n',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--list-aggregators',
        action='store_true',
        help='List available Config aggregators and exit'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

    # List aggregators if requested (no file logging needed for this)
    if args.list_aggregators:
        client = ConfigAggregatorClient(aggregator_name='', region=args.aggregator_region)
        aggregators = client.list_aggregators()
        if aggregators:
            print("Available Config Aggregators:")
            for agg in aggregators:
                print(f"  - {agg}")
        else:
            print("No Config aggregators found.")
        return

    # Set up file logging with account ID and region
    log_filename = get_log_filename(args.account, args.target_region)
    setup_file_logging(log_filename)
    logger.info(f"Logging to file: {log_filename}")

    # Build required tags dict
    required_tags = {
        'Customer': args.customer,
        'CostCenter': args.cost_center,
    }

    # Run the tagger
    tagger = NonCompliantResourceTagger(
        aggregator_name=args.aggregator,
        config_rule_name=args.config_rule,
        required_tags=required_tags,
        target_account=args.account,
        target_region=args.target_region,
        aggregator_region=args.aggregator_region,
        role_name=args.role_name,
        dry_run=args.dry_run,
    )
    tagger.run()


if __name__ == '__main__':
    main()
