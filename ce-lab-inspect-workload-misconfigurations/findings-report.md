# Security Misconfiguration Lab Report

## Identified Misconfigurations
1. **Public S3 Bucket**: `insecure-lab-ahmet` has Block Public Access disabled and a public ACL.
   - **STRIDE**: Information Disclosure (I)
2. **Open SSH Port**: Security group `insecure-ssh-sg` allows Port 22 from 0.0.0.0/0.
   - **STRIDE**: Denial of Service (D) / Spoofing (S)
3. **Over-privileged IAM Role**: `InsecureAppRole` has AdministratorAccess.
   - **STRIDE**: Elevation of Privilege (E)

## Detection Method
Used **AWS Config** with managed rules: `s3-bucket-public-read-prohibited` and `restricted-ssh`. Both resources were flagged as **NON_COMPLIANT**.

## Remediation Plan
- **S3**: Enable "Block Public Access" and remove public ACLs.
- **Security Group**: Restrict SSH access to my specific IP address only.
- **IAM**: Replace `AdministratorAccess` with a scoped-down policy using Least Privilege.
