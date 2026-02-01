# AWS IAM Fundamentals Lab: User & Group Management with Managed Policies

## Overview

This lab demonstrates core AWS Identity and Access Management (IAM) concepts:

- User, Group, and Role management
- Managed policy application
- Least-privilege enforcement
- Temporary credentials via STS
- MFA enforcement
- Trust modeling for internal and external auditors

The lab simulates a small team environment with Developers, Administrators, and Auditors.

---

## Goal / Why

- Understand how to organize IAM users and groups
- Enforce least privilege by using managed policies
- Verify access via AWS Console and CLI
- Apply real-world security practices for both internal and external auditors

---

## Scenario / Context

| Team        | Access Needs |
|------------|------------------------------------------------|
| Developers | S3 read/write, EC2 management |
| Administrators | Full administrative access |
| Auditors (Internal) | Read-only monitoring and compliance |
| Auditors (External) | Temporary, role-based read-only access via STS |

---

## Steps Taken

### 1. Root Account Security

- Logged into AWS root account **once**
- Enabled MFA
- Stored recovery information securely
- Root access restricted to emergencies

### 2. Create Admin IAM User

- User: `admin_user`
- Attached **AdministratorAccess-equivalent policy** for lab purposes:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

3. Create IAM Users

Users: dev_user, ops_user, audit_user

Enabled console access with temporary password


4. Create IAM Groups & Attach Managed Policies
Group	Managed Policies
Developers	AmazonS3FullAccess, AmazonEC2ReadOnlyAccess
Admins	AdministratorAccess
Auditors	ReadOnlyAccess


5. Assign Users to Groups

dev_user → Developers

ops_user → Admins

audit_user → Auditors


6. Create Resources

Created a sample S3 bucket for testing permissions


7. Verify Permissions

Logged in as each user via Console and CLI

Confirmed allowed actions matched group policies

Tested forbidden actions to verify denies

Observations

audit_user initially had AIOpsReadOnlyAccess, causing AccessDenied when listing S3 buckets

Managed policies differ in scope; using the wrong one can silently block services

Policy debugging sometimes requires user-level overrides temporarily

Actions & Fixes

Attached AmazonS3ReadOnlyAccess directly to audit_user for verification

Verified S3 access via CLI:

aws s3 ls --profile audit_user


Deleted user-level attachment and applied policy to Auditors group

Verified proper access

Lessons Learned

Always check policy permissions before assuming access

Groups are preferred over user-level permissions for manageability

Explicit denies override allows, regardless of user or group membership

MFA enforcement is critical

Policy Simulator is a helpful validation tool

"This lab intentionally mirrors real-world IAM evolution: from static user permissions → group-based access → temporary, role-based trust with enforced expiration."

Auditor Access Model
Internal Auditors

Standing read-only access governed by MFA and regular review

IAM user credentials long-lived

Group-based ReadOnlyAccess

External Auditors

Temporary STS credentials via AuditReadOnlyRole

TTL enforced automatically by AWS (expiration in UTC)

Eliminates long-lived secrets

Trust explicitly defined in role trust policy


Trust Flow Diagram:

External Auditor
   |
   | (Authenticate)
   v
IAM User / Federated Identity
   |
   | sts:AssumeRole (logged)
   v
AuditReadOnlyRole
   |
   | Temporary credentials (TTL enforced)
   v
Read-only access → auto-expire


Optional Security Enhancements

Enforce MFA for all users

Reduce external auditor TTL (15–60 minutes)

Restrict AssumeRole by time or IP

Monitor sts:AssumeRole events via CloudTrail

Outcome / Results

Users successfully created and grouped

Managed policies applied correctly

MFA enforced for all users

Principle of least privilege verified


Risks Exposed / Mitigated
Risk	Mitigation
Over-permission of Devs or Auditors	Used managed policies aligned with minimal necessary access
Orphaned accounts	Created regular audit process (to be automated later)
Lack of MFA	Enabled MFA to prevent compromised credentials
Next Steps / Improvements

Automate user/group creation with CloudFormation or Terraform

Use granular custom policies instead of broad managed ones

Integrate CloudTrail logging and monitoring

Evidence / Artifacts

Screenshots of IAM Console showing users and groups

CLI output of policy attachment and verification

Optional Policy Simulator screenshots

References

AWS IAM Best Practices
https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

AWS STS Temporary Credentials
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html

CIS AWS Foundations Benchmark
https://www.cisecurity.org/benchmark/amazon_web_services/
