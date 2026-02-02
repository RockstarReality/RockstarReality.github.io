#1 AWS IAM Fundamentals Lab: User & Group Management with Managed Policies

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








#2 AWS Security & Risk Concepts – Manual Access Audit

## Overview

This lab demonstrates a hands-on AWS IAM security review focused on identifying and mitigating **over-privileged access**, enforcing **least privilege**, and implementing **temporary, auditable administrative access** using IAM roles and STS — all within a **Free Tier, single-account environment**.

---

## Environment

- **Account Type:** Single AWS Account (Free Tier)
- **Tools Used:**  
  - AWS IAM Console  
  - IAM Access Analyzer  
  - AWS CloudTrail
- **Scope:** IAM Users, Groups, Roles
- **Limitations:**  
  - No AWS Organizations  
  - No paid security services

---

## 1. Scope & Objective

The objective of this review was to:

- Identify over-privileged IAM users
- Remove unnecessary standing permissions
- Replace persistent admin access with **temporary, role-based access**
- Ensure actions are **auditable and time-bound**
- Follow AWS least-privilege and security best practices

---

## 2. IAM Users Review (Console-Only)

### Users in Scope

- `admin_user`
- `ops_user`
- `dev_user`
- `audit_user`
- `test_user` (lab user)

---

### User: `admin_user`

**Attached Policies**
- `AdministratorAccess` (AWS managed)

**Group Membership**
- `Admins`

**Access Model**
- Standing administrative permissions via IAM user  
- No `AssumeRole` required  

---

### User: `ops_user`

**Attached Policies**
- `AdministratorAccess` (AWS managed)

**Group Membership**
- `Admins`

**Access Model**
- Standing administrative permissions via IAM user  
- No `AssumeRole` required  

---

### User: `dev_user`

**Attached Policies**
- `AmazonEC2ReadOnlyAccess`
- `AmazonS3FullAccess`

**Group Membership**
- `developers`

**Access Model**
- Standing permissions via IAM user  
- No `AssumeRole` required  

---

### User: `audit_user`

**Attached Policies**
- `ReadOnlyAccess` (AWS managed)

**Group Membership**
- `Auditors`

**Access Model**
- Standing read-only permissions via IAM user  

---

## 3. Orphaned Identity Handling (Lab Context)

- All access policies were removed from `test_user`
- Access was verified as fully revoked
- Demonstrated safe handling of unused or lab-only identities

**Security Lesson:**  
Orphaned users are low-hanging risk targets. Even inactive credentials can be abused if not removed.

---

## 4. IAM Access Analyzer (Free Tier)

IAM Access Analyzer was used to review the account for:

- Overly permissive access
- Unintended external access

**Result:**  
No external access findings were identified during this lab.

---

## 5. Creation of Temporary Administrative Role

An IAM role named **`AdminRole`** was created with the following configuration:

### Trusted Entity
- AWS Account (same account)

### Trust Relationship
- Only `ops_user` is allowed to assume the role
- MFA requirement enforced via trust policy condition

### Permissions
- `AdministratorAccess` (AWS managed policy)

### Access Model
- Role assumption via **AWS Console → Switch Role**
- Temporary credentials issued via STS
- No standing administrative privileges

This ensures administrative access is:
- Explicitly requested
- Time-bound
- Auditable

---

## 6. Removal of Standing Administrative Access

### ops_user

- Detached `AdministratorAccess` from:
  - User-level permissions
  - Group-level permissions
- Verified admin actions are not possible without assuming `AdminRole`

### admin_user

- Standing administrative access retained for **lab/root-equivalent purposes only**
- This exception is intentional, documented, and **not recommended for production**

---

## 7. Validation & Testing

### Role Assumption Test

- Logged in as `ops_user`
- Successfully assumed `AdminRole` using Switch Role
- Verified elevated privileges existed only within the role session

### Action Validation

- Created an S3 bucket while in `AdminRole`
- Deleted the same S3 bucket during the same role session
- Confirmed actions were not possible without assuming the role

**This confirms:**
- Trust relationship functions correctly
- Permissions are scoped to the role
- Access is temporary and controlled

---

## 8. Logging & Audit Evidence

- AWS CloudTrail was enabled
- Administrative actions were logged and verified
- CloudTrail event data was downloaded for lab verification
- Event details are not shared publicly due to personal security considerations

---

## 9. Key Security Lessons Learned

- IAM users should not hold standing administrative permissions
- Roles and STS significantly reduce blast radius
- Trust policies are as critical as permission policies
- Testing destructive actions validates real-world access
- Enterprise-grade security patterns are achievable even in Free Tier environments

Note on CloudTrail Identity Display
In the CloudTrail Event History summary view, events display the originating IAM user (ops_user). However, inspection of the full event record confirms the userIdentity.type as AssumedRole, with the action executed via the AdminRole using temporary STS credentials (ASIA...). This is expected CloudTrail behavior.

---


