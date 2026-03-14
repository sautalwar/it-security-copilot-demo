#!/usr/bin/env python3
"""Scenario 06 -- IaC Hardening: simulation script.

Creates insecure Infrastructure-as-Code templates (Azure Bicep and Terraform)
with common misconfigurations: public endpoints, missing encryption, weak
identity settings, and no diagnostic logging.
"""
from __future__ import annotations

import argparse
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "infra")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Insecure Azure Bicep template
# ---------------------------------------------------------------------------

INSECURE_BICEP = textwrap.dedent("""\
    // main.bicep -- INSECURE Azure infrastructure
    // WARNING: This template is intentionally misconfigured for demonstration.

    @description('Location for all resources')
    param location string = resourceGroup().location

    @description('Environment name')
    param environmentName string = 'prod'

    // ---- Storage Account (PUBLIC blob access) --------------------------------

    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'st${environmentName}data'
      location: location
      sku: {
        name: 'Standard_LRS'   // No redundancy
      }
      kind: 'StorageV2'
      properties: {
        allowBlobPublicAccess: true          // INSECURE: public blob access
        supportsHttpsTrafficOnly: false      // INSECURE: allows HTTP
        minimumTlsVersion: 'TLS1_0'         // INSECURE: weak TLS
        // No encryption scope configured
        // No blob versioning
        // No soft delete
      }
    }

    // ---- SQL Server (PUBLIC endpoint, no firewall) ---------------------------

    resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
      name: 'sql-${environmentName}-server'
      location: location
      properties: {
        administratorLogin: 'sqladmin'
        administratorLoginPassword: 'P@ssw0rd123!'   // INSECURE: hardcoded password
        publicNetworkAccess: 'Enabled'                // INSECURE: public endpoint
        // No Azure AD admin configured
        // No auditing
      }
    }

    resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
      parent: sqlServer
      name: 'appdb'
      location: location
      sku: {
        name: 'Basic'
      }
      properties: {
        // No TDE explicitly enabled (default may vary)
        // No long-term backup retention
      }
    }

    // Allow ALL Azure services (0.0.0.0) -- overly permissive
    resource sqlFirewallAll 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
      parent: sqlServer
      name: 'AllowAllAzureIPs'
      properties: {
        startIpAddress: '0.0.0.0'
        endIpAddress: '255.255.255.255'    // INSECURE: allows entire internet
      }
    }

    // ---- Virtual Network (no NSG) -------------------------------------------

    resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
      name: 'vnet-${environmentName}'
      location: location
      properties: {
        addressSpace: {
          addressPrefixes: ['10.0.0.0/16']
        }
        subnets: [
          {
            name: 'default'
            properties: {
              addressPrefix: '10.0.0.0/16'   // INSECURE: single giant subnet
              // No NSG association
              // No service endpoints
              // No delegation
            }
          }
        ]
        // No DDoS protection plan
      }
    }

    // ---- Key Vault (soft delete disabled) ------------------------------------

    resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
      name: 'kv-${environmentName}'
      location: location
      properties: {
        sku: {
          family: 'A'
          name: 'standard'
        }
        tenantId: subscription().tenantId
        enableSoftDelete: false              // INSECURE: no soft delete
        enablePurgeProtection: false         // INSECURE: no purge protection
        enableRbacAuthorization: false       // INSECURE: uses access policies
        accessPolicies: [
          {
            tenantId: subscription().tenantId
            objectId: '00000000-0000-0000-0000-000000000000'  // placeholder
            permissions: {
              keys: ['all']                  // INSECURE: overly broad
              secrets: ['all']
              certificates: ['all']
            }
          }
        ]
        // No network ACLs
        // No diagnostic settings
      }
    }

    // ---- App Service (HTTP allowed) -----------------------------------------

    resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
      name: 'plan-${environmentName}'
      location: location
      sku: {
        name: 'B1'
      }
    }

    resource webApp 'Microsoft.Web/sites@2023-01-01' = {
      name: 'app-${environmentName}'
      location: location
      properties: {
        serverFarmId: appServicePlan.id
        httpsOnly: false                     // INSECURE: HTTP allowed
        siteConfig: {
          minTlsVersion: '1.0'              // INSECURE: weak TLS
          ftpsState: 'AllAllowed'            // INSECURE: FTP allowed
          http20Enabled: false
          // No managed identity
          // No IP restrictions
        }
        // Using connection strings instead of managed identity
      }
    }
""")

# ---------------------------------------------------------------------------
# Insecure Terraform (AWS)
# ---------------------------------------------------------------------------

INSECURE_TERRAFORM = textwrap.dedent("""\
    # main.tf -- INSECURE AWS infrastructure
    # WARNING: This configuration is intentionally misconfigured for demonstration.

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

    # ---- S3 Bucket (PUBLIC ACL) -----------------------------------------------

    resource "aws_s3_bucket" "data" {
      bucket = "myapp-prod-data"

      tags = {
        Environment = "production"
      }
    }

    resource "aws_s3_bucket_acl" "data_acl" {
      bucket = aws_s3_bucket.data.id
      acl    = "public-read"               # INSECURE: public read access
    }

    # No encryption configuration
    # No versioning
    # No logging
    # No lifecycle rules
    # No public access block

    # ---- EC2 Instance (wide-open security group) ------------------------------

    resource "aws_security_group" "web_sg" {
      name        = "web-sg"
      description = "Security group for web servers"

      ingress {
        description = "Allow ALL traffic"
        from_port   = 0
        to_port     = 65535
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]        # INSECURE: open to the world
      }

      ingress {
        description = "SSH from anywhere"
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]        # INSECURE: SSH open to internet
      }

      egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }

    resource "aws_instance" "web" {
      ami           = "ami-0c55b159cbfafe1f0"
      instance_type = "t3.medium"

      vpc_security_group_ids = [aws_security_group.web_sg.id]

      # No key pair specified -- may use default or none
      # No IAM instance profile
      # No EBS encryption
      # No monitoring enabled

      tags = {
        Name = "web-server"
      }
    }

    # ---- RDS (publicly accessible) -------------------------------------------

    resource "aws_db_instance" "main" {
      identifier           = "myapp-prod-db"
      engine               = "postgres"
      engine_version       = "15.4"
      instance_class       = "db.t3.medium"
      allocated_storage    = 100
      db_name              = "app_production"
      username             = "admin"
      password             = "P@ssw0rd123!"       # INSECURE: hardcoded password
      publicly_accessible  = true                  # INSECURE: public endpoint
      skip_final_snapshot  = true                  # INSECURE: no final snapshot

      # No encryption at rest
      # No multi-AZ
      # No backup retention configured
      # No deletion protection
      # No performance insights
    }

    # ---- IAM Role (admin access) ---------------------------------------------

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

    resource "aws_iam_role_policy_attachment" "admin_access" {
      role       = aws_iam_role.app_role.name
      policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # INSECURE: full admin
    }
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    _ensure_dir(output_dir)

    # 1. Bicep
    bicep_path = os.path.join(output_dir, "main.bicep")
    with open(bicep_path, "w", encoding="utf-8") as f:
        f.write(INSECURE_BICEP)
    print(f"[+] Created INSECURE Bicep template -> {bicep_path}")

    # 2. Terraform
    tf_path = os.path.join(output_dir, "main.tf")
    with open(tf_path, "w", encoding="utf-8") as f:
        f.write(INSECURE_TERRAFORM)
    print(f"[+] Created INSECURE Terraform config -> {tf_path}")

    # Summary
    print()
    print("=== Simulation Summary ===")
    print(f"  Bicep template  : {bicep_path}")
    print(f"  Terraform config: {tf_path}")
    print()
    print("  Azure Bicep misconfigurations:")
    print("    - Storage Account: public blob access, HTTP allowed, TLS 1.0")
    print("    - SQL Server: hardcoded password, public endpoint, allow-all firewall")
    print("    - VNet: single /16 subnet, no NSG, no service endpoints")
    print("    - Key Vault: soft delete disabled, no purge protection, overly broad policies")
    print("    - App Service: HTTP allowed, TLS 1.0, FTP enabled, no managed identity")
    print()
    print("  Terraform (AWS) misconfigurations:")
    print("    - S3: public-read ACL, no encryption, no versioning")
    print("    - EC2: security group open 0.0.0.0/0 on all ports")
    print("    - RDS: publicly accessible, hardcoded password, no encryption")
    print("    - IAM: AdministratorAccess policy attached")
    print()
    print("[!] All templates have critical security gaps.  Run remediate.py to fix.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate insecure Infrastructure-as-Code templates.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory to write IaC files into (default: infra/).",
    )
    args = parser.parse_args()
    simulate(args.output_dir)


if __name__ == "__main__":
    main()
