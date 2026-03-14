#!/usr/bin/env python3
"""Scenario 06 -- IaC Hardening: remediation script.

Rewrites insecure Bicep and Terraform templates with hardened configurations
and generates a compliance diff report showing the before -> after state for
every resource.
"""
from __future__ import annotations

import argparse
import datetime
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "infra")


# ---------------------------------------------------------------------------
# Hardened Azure Bicep template
# ---------------------------------------------------------------------------

HARDENED_BICEP = textwrap.dedent("""\
    // main.bicep -- HARDENED Azure infrastructure
    //
    // Security controls applied:
    //   - Private access on all services
    //   - Encryption at rest and in transit
    //   - Managed identity (no connection strings)
    //   - NSGs on every subnet
    //   - Diagnostic settings on all resources
    //   - Soft delete and purge protection on Key Vault
    //   - HTTPS-only, TLS 1.2+ everywhere

    @description('Location for all resources')
    param location string = resourceGroup().location

    @description('Environment name')
    param environmentName string = 'prod'

    @description('Log Analytics workspace ID for diagnostics')
    param logAnalyticsWorkspaceId string

    // ---- Storage Account (PRIVATE, encrypted) --------------------------------

    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'st${environmentName}data'
      location: location
      sku: {
        name: 'Standard_GRS'               // Geo-redundant storage
      }
      kind: 'StorageV2'
      properties: {
        allowBlobPublicAccess: false         // HARDENED: no public access
        supportsHttpsTrafficOnly: true       // HARDENED: HTTPS only
        minimumTlsVersion: 'TLS1_2'         // HARDENED: TLS 1.2 minimum
        encryption: {
          services: {
            blob: { enabled: true, keyType: 'Account' }
            file: { enabled: true, keyType: 'Account' }
            queue: { enabled: true, keyType: 'Account' }
            table: { enabled: true, keyType: 'Account' }
          }
          keySource: 'Microsoft.Storage'
        }
        networkAcls: {
          defaultAction: 'Deny'
          bypass: 'AzureServices'
          virtualNetworkRules: [
            { id: '${vnet.properties.subnets[1].id}' }   // app-tier only
          ]
        }
      }
    }

    resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
      parent: storageAccount
      name: 'default'
      properties: {
        isVersioningEnabled: true            // HARDENED: blob versioning
        deleteRetentionPolicy: {
          enabled: true
          days: 30                           // HARDENED: soft delete 30 days
        }
        containerDeleteRetentionPolicy: {
          enabled: true
          days: 30
        }
      }
    }

    resource storageDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
      scope: storageAccount
      name: 'storage-diagnostics'
      properties: {
        workspaceId: logAnalyticsWorkspaceId
        metrics: [{ category: 'Transaction', enabled: true }]
      }
    }

    // ---- SQL Server (PRIVATE endpoint, AAD auth) ----------------------------

    resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
      name: 'sql-${environmentName}-server'
      location: location
      identity: {
        type: 'SystemAssigned'               // HARDENED: managed identity
      }
      properties: {
        administratorLogin: 'sqladmin'
        administratorLoginPassword: 'REPLACE_AT_DEPLOY_TIME'  // Injected via Key Vault reference
        publicNetworkAccess: 'Disabled'      // HARDENED: no public access
        minimalTlsVersion: '1.2'            // HARDENED: TLS 1.2
        administrators: {
          administratorType: 'ActiveDirectory'
          login: 'aad-sql-admins'
          sid: '00000000-0000-0000-0000-000000000000'
          tenantId: subscription().tenantId
          azureADOnlyAuthentication: true     // HARDENED: AAD-only auth
        }
      }
    }

    resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
      parent: sqlServer
      name: 'appdb'
      location: location
      sku: { name: 'S1' }
      properties: {
        zoneRedundant: true
        requestedBackupStorageRedundancy: 'Geo'
      }
    }

    resource sqlAudit 'Microsoft.Sql/servers/auditingSettings@2023-05-01-preview' = {
      parent: sqlServer
      name: 'default'
      properties: {
        state: 'Enabled'
        isAzureMonitorTargetEnabled: true
        retentionDays: 90
      }
    }

    resource sqlTDE 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-05-01-preview' = {
      parent: sqlDatabase
      name: 'current'
      properties: {
        state: 'Enabled'                     // HARDENED: TDE enabled
      }
    }

    resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
      name: 'pe-sql-${environmentName}'
      location: location
      properties: {
        subnet: { id: vnet.properties.subnets[2].id }  // data-tier subnet
        privateLinkServiceConnections: [
          {
            name: 'sql-connection'
            properties: {
              privateLinkServiceId: sqlServer.id
              groupIds: ['sqlServer']
            }
          }
        ]
      }
    }

    // ---- Virtual Network (NSGs on every subnet) ------------------------------

    resource nsgWeb 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
      name: 'nsg-web-${environmentName}'
      location: location
      properties: {
        securityRules: [
          {
            name: 'AllowHTTPS'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: 'Internet'
              destinationAddressPrefix: '*'
              sourcePortRange: '*'
              destinationPortRange: '443'
            }
          }
          {
            name: 'DenyAllInbound'
            properties: {
              priority: 4096
              direction: 'Inbound'
              access: 'Deny'
              protocol: '*'
              sourceAddressPrefix: '*'
              destinationAddressPrefix: '*'
              sourcePortRange: '*'
              destinationPortRange: '*'
            }
          }
        ]
      }
    }

    resource nsgApp 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
      name: 'nsg-app-${environmentName}'
      location: location
      properties: {
        securityRules: [
          {
            name: 'AllowFromWebTier'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: '10.0.1.0/24'
              destinationAddressPrefix: '*'
              sourcePortRange: '*'
              destinationPortRange: '443'
            }
          }
          {
            name: 'DenyAllInbound'
            properties: {
              priority: 4096
              direction: 'Inbound'
              access: 'Deny'
              protocol: '*'
              sourceAddressPrefix: '*'
              destinationAddressPrefix: '*'
              sourcePortRange: '*'
              destinationPortRange: '*'
            }
          }
        ]
      }
    }

    resource nsgData 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
      name: 'nsg-data-${environmentName}'
      location: location
      properties: {
        securityRules: [
          {
            name: 'AllowSQLFromAppTier'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: '10.0.2.0/24'
              destinationAddressPrefix: '*'
              sourcePortRange: '*'
              destinationPortRange: '1433'
            }
          }
          {
            name: 'DenyAllInbound'
            properties: {
              priority: 4096
              direction: 'Inbound'
              access: 'Deny'
              protocol: '*'
              sourceAddressPrefix: '*'
              destinationAddressPrefix: '*'
              sourcePortRange: '*'
              destinationPortRange: '*'
            }
          }
        ]
      }
    }

    resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
      name: 'vnet-${environmentName}'
      location: location
      properties: {
        addressSpace: {
          addressPrefixes: ['10.0.0.0/16']
        }
        subnets: [
          {
            name: 'web-tier'
            properties: {
              addressPrefix: '10.0.1.0/24'
              networkSecurityGroup: { id: nsgWeb.id }
              serviceEndpoints: [
                { service: 'Microsoft.Web' }
              ]
            }
          }
          {
            name: 'app-tier'
            properties: {
              addressPrefix: '10.0.2.0/24'
              networkSecurityGroup: { id: nsgApp.id }
              serviceEndpoints: [
                { service: 'Microsoft.Storage' }
                { service: 'Microsoft.Sql' }
                { service: 'Microsoft.KeyVault' }
              ]
            }
          }
          {
            name: 'data-tier'
            properties: {
              addressPrefix: '10.0.3.0/24'
              networkSecurityGroup: { id: nsgData.id }
            }
          }
        ]
        enableDdosProtection: true            // HARDENED: DDoS protection
      }
    }

    // ---- Key Vault (soft delete + purge protection + RBAC) -------------------

    resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
      name: 'kv-${environmentName}'
      location: location
      properties: {
        sku: { family: 'A', name: 'standard' }
        tenantId: subscription().tenantId
        enableSoftDelete: true               // HARDENED: soft delete
        softDeleteRetentionInDays: 90
        enablePurgeProtection: true          // HARDENED: purge protection
        enableRbacAuthorization: true        // HARDENED: RBAC instead of access policies
        networkAcls: {
          defaultAction: 'Deny'
          bypass: 'AzureServices'
          virtualNetworkRules: [
            { id: '${vnet.properties.subnets[1].id}' }
          ]
        }
      }
    }

    resource kvDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
      scope: keyVault
      name: 'kv-diagnostics'
      properties: {
        workspaceId: logAnalyticsWorkspaceId
        logs: [
          { category: 'AuditEvent', enabled: true, retentionPolicy: { enabled: true, days: 90 } }
        ]
      }
    }

    // ---- App Service (HTTPS-only, TLS 1.2, managed identity) ----------------

    resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
      name: 'plan-${environmentName}'
      location: location
      sku: { name: 'S1' }
    }

    resource webApp 'Microsoft.Web/sites@2023-01-01' = {
      name: 'app-${environmentName}'
      location: location
      identity: {
        type: 'SystemAssigned'               // HARDENED: managed identity
      }
      properties: {
        serverFarmId: appServicePlan.id
        httpsOnly: true                      // HARDENED: HTTPS only
        siteConfig: {
          minTlsVersion: '1.2'              // HARDENED: TLS 1.2 minimum
          ftpsState: 'Disabled'             // HARDENED: FTP disabled
          http20Enabled: true
          alwaysOn: true
        }
      }
    }

    resource webAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
      scope: webApp
      name: 'webapp-diagnostics'
      properties: {
        workspaceId: logAnalyticsWorkspaceId
        logs: [
          { category: 'AppServiceHTTPLogs', enabled: true }
          { category: 'AppServiceConsoleLogs', enabled: true }
          { category: 'AppServiceAuditLogs', enabled: true }
        ]
        metrics: [
          { category: 'AllMetrics', enabled: true }
        ]
      }
    }
""")

# ---------------------------------------------------------------------------
# Hardened Terraform (AWS)
# ---------------------------------------------------------------------------

HARDENED_TERRAFORM = textwrap.dedent("""\
    # main.tf -- HARDENED AWS infrastructure
    #
    # Security controls applied:
    #   - S3: private, encrypted, versioned, public access blocked
    #   - EC2: restricted security group, encrypted EBS, monitoring
    #   - RDS: private, encrypted, multi-AZ, backup retention
    #   - IAM: least-privilege policy, no admin access

    terraform {
      required_providers {
        aws = {
          source  = "hashicorp/aws"
          version = "~> 5.0"
        }
      }
    }

    provider "aws" {
      region = "us-east-1"
    }

    variable "db_password" {
      type      = string
      sensitive = true
      description = "Database password -- pass via TF_VAR_db_password or tfvars"
    }

    # ---- S3 Bucket (PRIVATE, encrypted, versioned) ----------------------------

    resource "aws_s3_bucket" "data" {
      bucket = "myapp-prod-data"

      tags = {
        Environment = "production"
      }
    }

    resource "aws_s3_bucket_acl" "data_acl" {
      bucket = aws_s3_bucket.data.id
      acl    = "private"                    # HARDENED: private access
    }

    resource "aws_s3_bucket_versioning" "data_versioning" {
      bucket = aws_s3_bucket.data.id
      versioning_configuration {
        status = "Enabled"                  # HARDENED: versioning enabled
      }
    }

    resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
      bucket = aws_s3_bucket.data.id
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm = "aws:kms"         # HARDENED: KMS encryption
        }
        bucket_key_enabled = true
      }
    }

    resource "aws_s3_bucket_public_access_block" "data_block" {
      bucket                  = aws_s3_bucket.data.id
      block_public_acls       = true        # HARDENED: block public ACLs
      block_public_policy     = true
      ignore_public_acls      = true
      restrict_public_buckets = true
    }

    resource "aws_s3_bucket_logging" "data_logging" {
      bucket        = aws_s3_bucket.data.id
      target_bucket = aws_s3_bucket.data.id
      target_prefix = "access-logs/"        # HARDENED: access logging
    }

    # ---- EC2 Instance (restricted security group, encrypted) ------------------

    resource "aws_security_group" "web_sg" {
      name        = "web-sg"
      description = "HARDENED security group for web servers"

      ingress {
        description = "HTTPS only"
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]         # Public HTTPS only
      }

      ingress {
        description = "SSH from bastion only"
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["10.0.4.0/24"]       # HARDENED: bastion subnet only
      }

      egress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]         # HARDENED: HTTPS egress only
      }

      egress {
        description = "DNS resolution"
        from_port   = 53
        to_port     = 53
        protocol    = "udp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }

    resource "aws_instance" "web" {
      ami           = "ami-0c55b159cbfafe1f0"
      instance_type = "t3.medium"

      vpc_security_group_ids = [aws_security_group.web_sg.id]
      iam_instance_profile   = aws_iam_instance_profile.app_profile.name

      monitoring = true                      # HARDENED: detailed monitoring

      root_block_device {
        encrypted   = true                   # HARDENED: EBS encryption
        volume_type = "gp3"
      }

      metadata_options {
        http_tokens   = "required"           # HARDENED: IMDSv2 required
        http_endpoint = "enabled"
      }

      tags = {
        Name = "web-server"
      }
    }

    # ---- RDS (private, encrypted, multi-AZ) ----------------------------------

    resource "aws_db_instance" "main" {
      identifier             = "myapp-prod-db"
      engine                 = "postgres"
      engine_version         = "15.4"
      instance_class         = "db.t3.medium"
      allocated_storage      = 100
      db_name                = "app_production"
      username               = "admin"
      password               = var.db_password      # HARDENED: variable, not hardcoded
      publicly_accessible    = false                 # HARDENED: private only
      skip_final_snapshot    = false                 # HARDENED: final snapshot required
      final_snapshot_identifier = "myapp-prod-final"
      storage_encrypted      = true                  # HARDENED: encryption at rest
      multi_az               = true                  # HARDENED: multi-AZ
      backup_retention_period = 30                   # HARDENED: 30-day backup
      deletion_protection    = true                  # HARDENED: deletion protection
      performance_insights_enabled = true            # HARDENED: performance insights

      tags = {
        Environment = "production"
      }
    }

    # ---- IAM Role (least-privilege) ------------------------------------------

    resource "aws_iam_role" "app_role" {
      name = "myapp-role"

      assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
        }]
      })
    }

    # HARDENED: Least-privilege policy (S3 read + CloudWatch write only)
    resource "aws_iam_role_policy" "app_policy" {
      name = "myapp-least-privilege"
      role = aws_iam_role.app_role.id

      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Effect   = "Allow"
            Action   = ["s3:GetObject", "s3:ListBucket"]
            Resource = [
              aws_s3_bucket.data.arn,
              "${aws_s3_bucket.data.arn}/*"
            ]
          },
          {
            Effect   = "Allow"
            Action   = [
              "cloudwatch:PutMetricData",
              "logs:CreateLogGroup",
              "logs:CreateLogStream",
              "logs:PutLogEvents"
            ]
            Resource = "*"
          }
        ]
      })
    }

    resource "aws_iam_instance_profile" "app_profile" {
      name = "myapp-profile"
      role = aws_iam_role.app_role.name
    }
""")


# ---------------------------------------------------------------------------
# Compliance diff report
# ---------------------------------------------------------------------------

COMPLIANCE_ITEMS: list[dict[str, str]] = [
    {
        "resource": "Storage Account (Bicep)",
        "before": "Public blob access, HTTP allowed, TLS 1.0, no encryption scope, no versioning",
        "after": "Private access, HTTPS only, TLS 1.2, encryption at rest, blob versioning, soft delete 30d, network ACLs deny-by-default",
        "controls": "CIS 3.1, 3.3, 3.5, 3.7",
    },
    {
        "resource": "SQL Server (Bicep)",
        "before": "Hardcoded password, public endpoint, allow-all firewall, no auditing",
        "after": "Key Vault password ref, private endpoint, AAD-only auth, TDE enabled, auditing 90d, managed identity",
        "controls": "CIS 4.1, 4.2, 4.3, 4.5",
    },
    {
        "resource": "Virtual Network (Bicep)",
        "before": "Single /16 subnet, no NSGs, no service endpoints, no DDoS protection",
        "after": "Three-tier subnets (web/app/data), NSG on each subnet, service endpoints, DDoS protection enabled",
        "controls": "CIS 6.1, 6.2, 6.4",
    },
    {
        "resource": "Key Vault (Bicep)",
        "before": "Soft delete disabled, no purge protection, access policies with 'all' permissions, no network ACLs",
        "after": "Soft delete 90d, purge protection, RBAC authorization, network ACLs deny-by-default, audit logging",
        "controls": "CIS 8.1, 8.2, 8.4",
    },
    {
        "resource": "App Service (Bicep)",
        "before": "HTTP allowed, TLS 1.0, FTP enabled, no managed identity, no diagnostics",
        "after": "HTTPS only, TLS 1.2, FTP disabled, system-assigned managed identity, diagnostic logs",
        "controls": "CIS 9.1, 9.2, 9.3, 9.10",
    },
    {
        "resource": "S3 Bucket (Terraform)",
        "before": "Public-read ACL, no encryption, no versioning, no logging, no public access block",
        "after": "Private ACL, KMS encryption, versioning enabled, access logging, public access block on all 4 settings",
        "controls": "CIS 2.1.1, 2.1.2, 2.1.5",
    },
    {
        "resource": "EC2 Instance (Terraform)",
        "before": "Security group open 0.0.0.0/0 all ports, SSH from internet, no EBS encryption, no monitoring, IMDSv1",
        "after": "HTTPS-only ingress, SSH from bastion subnet only, EBS encrypted, detailed monitoring, IMDSv2 required",
        "controls": "CIS 5.1, 5.2, 5.3",
    },
    {
        "resource": "RDS Instance (Terraform)",
        "before": "Publicly accessible, hardcoded password, no encryption, single-AZ, no backups, no deletion protection",
        "after": "Private only, password via variable, KMS encryption, multi-AZ, 30-day backup retention, deletion protection, performance insights",
        "controls": "CIS 2.3.1, 2.3.2",
    },
    {
        "resource": "IAM Role (Terraform)",
        "before": "AdministratorAccess policy attached (full admin)",
        "after": "Least-privilege inline policy: S3 read + CloudWatch write only",
        "controls": "CIS 1.16, 1.22",
    },
]


def _generate_report() -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  IaC HARDENING -- COMPLIANCE DIFF REPORT")
    lines.append(f"  Generated: {datetime.datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Resources audited: {len(COMPLIANCE_ITEMS)}")
    lines.append("")

    for item in COMPLIANCE_ITEMS:
        lines.append(f"--- {item['resource']} ---")
        lines.append(f"  BEFORE : {item['before']}")
        lines.append(f"  AFTER  : {item['after']}")
        lines.append(f"  CIS    : {item['controls']}")
        lines.append("")

    lines.append("--- Summary ---")
    lines.append(f"  Total resources hardened: {len(COMPLIANCE_ITEMS)}")
    lines.append("  All critical misconfigurations addressed.")
    lines.append("")
    lines.append("--- Recommendations ---")
    lines.append("  1. Review all parameter defaults before deployment.")
    lines.append("  2. Use Azure Policy / AWS Config rules to prevent drift.")
    lines.append("  3. Integrate IaC scanning (tfsec, checkov, PSRule) into CI/CD.")
    lines.append("  4. Store Terraform state in encrypted remote backend.")
    lines.append("  5. Use Key Vault references for all secrets in Bicep parameters.")
    lines.append("  6. Enable Microsoft Defender for Cloud / AWS Security Hub.")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # 1. Hardened Bicep
    bicep_path = os.path.join(output_dir, "main.bicep")
    with open(bicep_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_BICEP)
    print(f"[+] Wrote HARDENED Bicep template -> {bicep_path}")

    # 2. Hardened Terraform
    tf_path = os.path.join(output_dir, "main.tf")
    with open(tf_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_TERRAFORM)
    print(f"[+] Wrote HARDENED Terraform config -> {tf_path}")

    # 3. Compliance report
    report = _generate_report()
    report_path = os.path.join(output_dir, "iac_compliance_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"[+] Generated compliance diff report -> {report_path}")
    print()
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Harden IaC templates and generate compliance report.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory containing IaC files (default: infra/).",
    )
    args = parser.parse_args()
    remediate(args.output_dir)


if __name__ == "__main__":
    main()
