# Lab M8.02 - Inspect Workload Misconfiguration Examples

**Repository:** [https://github.com/cloud-engineering-bootcamp/ce-lab-inspect-workload-misconfigurations](https://github.com/cloud-engineering-bootcamp/ce-lab-inspect-workload-misconfigurations)

**Activity Type:** Individual  
**Estimated Time:** 60 minutes

## Learning Objectives

- [ ] Identify common cloud security misconfigurations
- [ ] Use AWS Config to detect security issues
- [ ] Analyze misconfigured IAM roles, security groups, and S3 buckets
- [ ] Write simple threat models using STRIDE
- [ ] Document findings and propose remediations

## Prerequisites

- [ ] Completed Module 8 Lesson 2
- [ ] AWS account with Config enabled
- [ ] Basic understanding of security threats

## Introduction

In this lab, you'll intentionally create misconfigurations (in a safe environment), detect them using AWS tools, and document the security risks. This hands-on experience will help you recognize and prevent real-world security issues.

## Your Task

**What you'll create:**
- Intentionally misconfigured resources (S3, security group, IAM)
- Detection of misconfigurations using AWS Config
- Threat model (STRIDE) for a simple web application
- Remediation plan with priorities

**Success criteria:**
- [ ] Created 3 intentional misconfigurations
- [ ] Detected misconfigurations with AWS Config
- [ ] Completed STRIDE threat model
- [ ] Documented 5 common threats with mitigations
- [ ] Remediated all misconfigurations

**Time limit:** 60 minutes

## Step 1: Create Intentional Misconfigurations

### Misconfiguration 1: Public S3 Bucket

```bash
# Create a bucket with public access
aws s3 mb s3://my-insecure-test-bucket-$(date +%s)

# Disable Block Public Access
aws s3api put-public-access-block \
  --bucket my-insecure-test-bucket-1234567890 \
  --public-access-block-configuration \
  "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

# Upload a test file
echo "This is sensitive data" > test-file.txt
aws s3 cp test-file.txt s3://my-insecure-test-bucket-1234567890/

# Make it public
aws s3api put-object-acl \
  --bucket my-insecure-test-bucket-1234567890 \
  --key test-file.txt \
  --acl public-read
```

**Document the risk:**
```markdown
## Misconfiguration 1: Public S3 Bucket
- **Threat:** Information Disclosure (STRIDE: I)
- **Risk Level:** Critical
- **Impact:** Customer PII exposed to internet
- **Detection:** AWS Config rule s3-bucket-public-read-prohibited
```

### Misconfiguration 2: Overly Permissive Security Group

```bash
# Create security group with SSH open to world
aws ec2 create-security-group \
  --group-name insecure-ssh-sg \
  --description "Intentionally insecure SG for lab"

# Allow SSH from 0.0.0.0/0
aws ec2 authorize-security-group-ingress \
  --group-name insecure-ssh-sg \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

**Document the risk:**
```markdown
## Misconfiguration 2: SSH Open to Internet
- **Threat:** Unauthorized Access (STRIDE: S - Spoofing)
- **Risk Level:** Critical
- **Impact:** Brute force attacks, potential instance compromise
- **Detection:** AWS Config rule restricted-ssh
```

### Misconfiguration 3: IAM Role with Administrator Access

```bash
# Create IAM role with excessive permissions
aws iam create-role \
  --role-name InsecureAppRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach AdministratorAccess policy
aws iam attach-role-policy \
  --role-name InsecureAppRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Document the risk:**
```markdown
## Misconfiguration 3: Overly Permissive IAM Role
- **Threat:** Elevation of Privilege (STRIDE: E)
- **Risk Level:** Critical
- **Impact:** Compromised application can access all AWS resources
- **Detection:** IAM Access Analyzer, manual review
```

## Step 2: Detect Misconfigurations with AWS Config

### Enable AWS Config (if not already enabled)

```bash
# Create S3 bucket for Config logs
aws s3 mb s3://aws-config-bucket-$(date +%s)

# Enable Config
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::YOUR_ACCOUNT:role/config-role

# Start recording
aws configservice start-configuration-recorder \
  --configuration-recorder-name default
```

### Add Config Rules

```bash
# Rule to detect public S3 buckets
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
  }'

# Rule to detect open SSH
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "restricted-ssh",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "INCOMING_SSH_DISABLED"
    }
  }'

# Wait for evaluation (5-10 minutes)
```

### Check Compliance

```bash
# View non-compliant resources
aws configservice describe-compliance-by-config-rule \
  --config-rule-names s3-bucket-public-read-prohibited restricted-ssh
```

**Expected output:**
```json
{
  "ComplianceByConfigRules": [
    {
      "ConfigRuleName": "s3-bucket-public-read-prohibited",
      "Compliance": {
        "ComplianceType": "NON_COMPLIANT"
      }
    },
    {
      "ConfigRuleName": "restricted-ssh",
      "Compliance": {
        "ComplianceType": "NON_COMPLIANT"
      }
    }
  ]
}
```

## Step 3: Write STRIDE Threat Model

Create `threat-model.md`:

```markdown
# Threat Model: Simple Web Application

## Architecture
- Frontend: React app (S3 + CloudFront)
- Backend: Node.js API (ALB + EC2)
- Database: PostgreSQL (RDS)

## Assets
- Customer PII in database
- User session tokens
- API keys for third-party services

## STRIDE Analysis

### S - Spoofing
**Threat:** Attacker steals user session cookie
- **Mitigation:** HttpOnly cookies, short-lived tokens, MFA
- **Priority:** High

### T - Tampering
**Threat:** SQL injection modifies data
- **Mitigation:** Parameterized queries, input validation, WAF
- **Priority:** Critical

### R - Repudiation
**Threat:** User denies placing order
- **Mitigation:** CloudTrail logs, application audit trail
- **Priority:** Medium

### I - Information Disclosure
**Threat:** Public S3 bucket exposes data
- **Mitigation:** S3 Block Public Access, encryption
- **Priority:** Critical

### D - Denial of Service
**Threat:** DDoS attack on ALB
- **Mitigation:** AWS Shield, CloudFront, rate limiting
- **Priority:** Medium

### E - Elevation of Privilege
**Threat:** EC2 role has admin access
- **Mitigation:** Least privilege IAM, regular reviews
- **Priority:** Critical
```

## Step 4: Remediate Misconfigurations

### Remediation 1: Secure S3 Bucket

```bash
# Enable Block Public Access
aws s3api put-public-access-block \
  --bucket my-insecure-test-bucket-1234567890 \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket my-insecure-test-bucket-1234567890 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Verify
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited
```

### Remediation 2: Restrict Security Group

```bash
# Remove 0.0.0.0/0 rule
aws ec2 revoke-security-group-ingress \
  --group-name insecure-ssh-sg \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add restricted rule (corporate VPN or bastion)
aws ec2 authorize-security-group-ingress \
  --group-name insecure-ssh-sg \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.0/24  # Corporate VPN CIDR
```

### Remediation 3: Apply Least Privilege IAM

```bash
# Detach AdministratorAccess
aws iam detach-role-policy \
  --role-name InsecureAppRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create least-privilege policy
cat > app-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-app-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:prod/db/*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name InsecureAppRole \
  --policy-name AppLeastPrivilegePolicy \
  --policy-document file://app-policy.json
```

## Step 5: Document Findings

Create `findings-report.md`:

```markdown
# Security Misconfiguration Lab Report

## Misconfigurations Identified

| # | Misconfiguration | Risk Level | Remediation | Status |
|---|------------------|------------|-------------|--------|
| 1 | Public S3 bucket | Critical | Enable Block Public Access, encryption | ✅ Fixed |
| 2 | SSH open to 0.0.0.0/0 | Critical | Restrict to corporate VPN | ✅ Fixed |
| 3 | IAM AdministratorAccess | Critical | Apply least privilege | ✅ Fixed |

## Detection Methods
- AWS Config rules (automated)
- Manual review (IAM policies)

## Lessons Learned
1. Default-deny is critical (Block Public Access)
2. Regular Config rule evaluation catches misconfigurations
3. IAM Access Analyzer should be enabled for ongoing monitoring

## Recommendations
1. Enable Security Hub for centralized findings
2. Implement infrastructure as code to enforce secure baselines
3. Conduct quarterly security reviews
```

## Submission

Submit:
1. **`threat-model.md`** - STRIDE analysis
2. **`findings-report.md`** - Misconfigurations and remediations
3. **Screenshots** - Config non-compliant findings before and after remediation

## Verification Checklist

- [ ] All 3 misconfigurations created and documented
- [ ] Config rules detected misconfigurations
- [ ] STRIDE threat model completed
- [ ] All misconfigurations remediated
- [ ] Config rules show compliant status

## Cleanup

**Important: Delete test resources to avoid charges**

```bash
# Delete S3 bucket
aws s3 rb s3://my-insecure-test-bucket-1234567890 --force

# Delete security group
aws ec2 delete-security-group --group-name insecure-ssh-sg

# Delete IAM role
aws iam detach-role-policy --role-name InsecureAppRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name InsecureAppRole
```

## Additional Resources

- [AWS Config Rules Reference](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Top 10 Cloud Security Risks](https://owasp.org/www-project-cloud-security/)

**Good luck! 🔒**
