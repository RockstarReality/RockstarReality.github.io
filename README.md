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

Due to lab time constraints, STS credential expiration was not waited on in real time; however, session-based access was validated by confirming the inability to perform administrative actions outside an assumed role.
STS Credential Expiration Validation:
Role assumption events were inspected in AWS CloudTrail. The AssumeRole event record confirms that temporary STS credentials were issued with a fixed expiration timestamp. Additionally, the role’s maximum session duration enforces an upper bound on credential lifetime, ensuring access cannot persist indefinitely. Active role sessions can also be manually revoked, immediately invalidating temporary credentials.

---

# 3.1 IAM Privilege Escalation via IAM PassRole — Offensive Lab Report with Remediation


## Executive Summary

This report documents a hands‑on offensive security lab conducted in an AWS Free Tier account using **console‑only access**. The objective was to simulate a real-world attacker who gains access to a **low‑privileged IAM user** and attempts to escalate privileges through **IAM trust and permission misconfigurations**.

The lab successfully demonstrated a **critical privilege-escalation path** using the `iam:PassRole` permission combined with minimal EC2 permissions. Although the attacker identity never became an IAM administrator, they were able to cause AWS services to execute with **full administrative privileges**, representing a complete compromise in practice.

---

## Scope & Constraints

- **Environment**: AWS Free Tier account
    
- **Access Method**: AWS Management Console (browser only)
    
- **Out of Scope**: AWS CLI / SDK usage, EC2 shell access, real production resources
    

---

## Initial Conditions

- **Attacker User**: `attacker-user`
    
- **Permissions**: `iam:Get*`, `iam:List*`, `iam:PassRole`, minimal EC2 permissions (`RunInstances`, required `Describe*`)
    
- **Target Role**: `AdminEC2Role` with `AdministratorAccess` trusted by EC2
    

---

## Attack Narrative

1. **Reconnaissance**: Enumerated IAM roles and discovered `AdminEC2Role` as a high-value target.
    
2. **Failed Direct Role Assumption**: Switch Role attempts failed, confirming trust policy enforced indirect escalation.
    
3. **PassRole Exploitation via EC2**: Using the EC2 launch workflow, the attacker successfully selected `AdminEC2Role` in the IAM instance profile dropdown and launched an instance with administrative privileges.
    
4. **Least-Privilege Friction**: Attacker could not see EC2 instances (`ec2:DescribeInstances` denied) but impact was still achieved.
    
5. **Console vs Role Identity**: Attempts to create IAM policies failed because the attacker identity in the console did not inherit EC2 role credentials.
    

---

## Impact Assessment

- Arbitrary compute resources with `AdministratorAccess` can be launched
    
- Ability to exfiltrate data, modify infrastructure, establish persistence, and perform lateral movement
    
- Severity: **Critical – Full account compromise via service role abuse**
    

---

## Root Cause Analysis

- Broad `iam:PassRole` without conditions
    
- High-privilege role trusted by EC2
    
- Minimal EC2 execution permissions
    
- No permission boundaries or monitoring
    
- Cross-service permission composition overlooked
    

---

## Remediation & Hardening Checklist

### 1. Restrict `iam:PassRole` Usage

```json
"Condition": {
  "StringEquals": {
    "iam:PassedToService": "ec2.amazonaws.com"
  }
}
```

- Only allow roles to be passed to specific services that require them
    
- Audit all users and policies with `iam:PassRole` privileges
    

### 2. Enforce Permission Boundaries

- Apply IAM permission boundaries to high-privilege roles
    
- Prevent roles from exceeding intended access even if `PassRole` is abused
    

### 3. Harden Trust Policies

- Restrict service principals to only what is necessary
    
- Avoid overly broad `*` trust relationships
    

### 4. Implement Monitoring & Detection

- Enable CloudTrail logging for all `iam:PassRole`, `RunInstances`, and sensitive actions
    
- Set up alerts for unusual role attachment or privilege escalation patterns
    

### 5. Periodic IAM Graph Analysis

- Regularly analyze combined permissions across users, roles, and services
    
- Identify risky compositions before they are exploited
    

### 6. Security Awareness & Least-Privilege Enforcement

- Educate devs and admins about risks of PassRole
    
- Use managed policies and service-linked roles whenever possible
    
- Review Free Tier / lab accounts for unnecessary privileges
    

---

## Conclusion

This lab demonstrates that **least-privilege enforcement must consider cross-service interactions**, not just individual IAM policies. Even when visibility and console actions are restricted, `iam:PassRole` can be exploited for **full administrative compromise**. Implementing the remediation checklist above will significantly reduce the risk of privilege escalation.

---

**Lab Outcome:**

- Privilege escalation achieved via EC2
    
- Console limitations respected
    
- Root cause and mitigation fully documented
    
- Hardening checklist provided for operational security
    

---

## Remediation Checklist & IAM Redesign

This section translates the offensive lab into **actionable defensive controls**. The goal is not to patch a single bug, but to eliminate the entire _class_ of IAM privilege‑escalation failures.

---

## 1. Immediate Containment Actions (High Priority)

### 1.1 Restrict `iam:PassRole`

**Action:**

- Inventory all principals with `iam:PassRole`
    
- Remove wildcard role resources
    

**Secure Pattern:**

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/SpecificRole",
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "ecs-tasks.amazonaws.com"
    }
  }
}
```

**Security Lesson:**  
`iam:PassRole` without `iam:PassedToService` is equivalent to administrator access by proxy.

---

### 1.2 Rotate or Disable Abused Roles

**Action:**

- Detach admin policies temporarily
    
- Review CloudTrail for recent `AssumeRole`
    

**Why:**  
STS credentials remain valid after abuse unless explicitly mitigated.

---

## 2. Role Trust Policy Hardening

### 2.1 Scope Service Trusts

**Insecure:**

```json
{"Principal": {"Service": "ec2.amazonaws.com"}}
```

**Hardened:**

```json
{
  "Principal": {"Service": "ec2.amazonaws.com"},
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "<ACCOUNT_ID>"
    }
  }
}
```

---

### 2.2 Separate Human vs Service Roles

**Rule:**

- Humans assume roles
    
- Services execute roles
    
- Never both
    

This blocks lateral trust abuse.

---

## 3. Permission Boundaries (Critical Control)

Apply permission boundaries to **all** execution roles.

```json
{
  "Effect": "Deny",
  "Action": ["iam:*", "organizations:*"],
  "Resource": "*"
}
```

Even if a role is misused, IAM remains protected.

---

## 4. IAM Policy Redesign

### 4.1 Avoid Broad Read Permissions

Replace:

```json
"iam:Get*", "iam:List*"
```

With resource‑scoped reads where possible.

---

### 4.2 Review Permission Composition

Ask:

> What happens if this identity gains _one more_ permission?

IAM failures occur at **policy intersections**.

---

## 5. Monitoring & Detection

Alert on:

- `iam:PassRole`
    
- `RunInstances`
    
- High‑privilege role assumption
    

Correlate events — not single actions.

---

## 6. Organizational IAM Design Principles

- Separate execution, admin, and human roles
    
- Treat privilege‑escalation APIs as break‑glass
    
- Prefer temporary credentials everywhere
    

---

## Final Takeaway

> AWS services will faithfully execute whatever IAM allows.

Security failures happen when trust boundaries blur — not when attackers are clever.

---



# 3.2 LAB 2 SUMMARY — Social Engineering Through IAM


## What This Lab Demonstrated

LAB 2 focused on **social engineering risk in AWS IAM**, not deep technical exploitation.

We modeled a realistic access request by creating a low‑privilege identity (`guest-contractor`) that would normally pass review:

- No administrator permissions
    
- No IAM write access
    
- No ability to assume roles directly
    

The user was intentionally framed as a contractor / guest account.

---

## The Social Engineering Angle

The risk did not come from obvious power.  
It came from a **subtle permission (`iam:PassRole`) that is commonly misunderstood and approved**.

From a reviewer’s perspective, this user looked safe.  
From an attacker’s perspective, this user could influence AWS services to act with elevated privileges.

This gap between perception and reality is where social engineering succeeds in cloud environments.

---

## Key Takeaway

> A user does not need admin permissions to create admin impact.

Even though the EC2 launch ultimately failed due to a missing permission, the **attack path existed**.  
That makes this a latent, high‑risk misconfiguration — not a false alarm.

---

## Why This Matters Before LAB 3

LAB 2 proves that individual access reviews can fail even when everyone acts in good faith.

LAB 3 will expand this into a **multi‑user environment**, showing how many small, reasonable permissions combine into systemic compromise.

---

_End of LAB 2 Summary_

---



# 3.3 AWS IAM Privilege Escalation Case Study


## Social Engineering + CLI‑Based PassRole Abuse

---

## Executive Summary

This case study documents a controlled AWS lab exercise demonstrating how **IAM misconfigurations involving `iam:PassRole` can lead to privilege escalation**, even when traditional console‑based protections are in place.

The lab highlights a realistic attacker progression:

1. **Initial access via low‑privileged automation credentials**
    
2. **Console‑based escalation attempts blocked by IAM hardening**
    
3. **Pivot to AWS CLI (PowerShell)**
    
4. **Successful privilege escalation through EC2 role attachment**
    
5. **Creation of persistent administrator‑privileged infrastructure without lifecycle control**
    

A key outcome of this exercise is the distinction between **browser‑based security controls** and **programmatic/API threat models**, demonstrating that **console guardrails alone are insufficient** to prevent escalation when automation permissions are misaligned.

---

## Lab Objectives

- Demonstrate differences between **console‑based** and **CLI‑based** attack surfaces
    
- Show how `iam:PassRole` can be abused **without IAM visibility**
    
- Illustrate real‑world **social engineering trust failures**
    
- Highlight risks of **automation users creating privileged infrastructure**
    
- Emphasize the danger of **creation permissions without lifecycle control**
    

---

## Environment Overview

### IAM Users

|User|Intended Role|
|---|---|
|**ops-junior**|Junior operations, EC2 via console|
|**ci-helper**|CI / automation user (CLI access)|
|**dev-automation**|Lambda automation experiments|
|**dev-readonly / security-auditor**|IAM read-only visibility|
|**guest-contractor**|Minimal / no permissions|

---

### IAM Roles

#### **AdminEC2Role**

- **Trust**: `ec2.amazonaws.com`
    
- **Policy**: `AdministratorAccess`
    
- **Purpose**: Administrative EC2 workloads
    
- ⚠️ High‑risk role
    

#### **AutomationRole**

- **Trust**: `ec2.amazonaws.com`, `lambda.amazonaws.com`
    
- **Policy**: EC2 + SSM permissions
    
- **Status**: Orphaned / over‑trusted
    

#### **ReadOnlyAuditRole**

- **Trust**: IAM users in account
    
- **Policy**: `SecurityAudit`
    

---

## LAB 2 — Social Engineering & Access Modeling (Context)

LAB 2 focused on **human trust boundaries**, not technical exploitation.

Key observations:

- Junior staff relied on **console visibility** to judge safety
    
- Automation users were implicitly trusted
    
- Role names and infrastructure details were casually shared
    
- No malicious intent — only **assumed trust**
    

This laid the groundwork.

---

## LAB 3 — CLI‑Based Privilege Escalation via PassRole

### Threat Model

The attacker (ci-helper) did **not** possess full automation credentials or independent infrastructure design capability. Instead, the attacker relied on **social engineering of a junior operations user** to obtain a valid EC2 launch blueprint, including the AMI ID, instance type, region, and knowledge of a privileged IAM role.

While console-based IAM controls successfully prevented role discovery and selection, this human trust boundary bridged the remaining gaps. Once the attacker obtained a known-good configuration, `iam:PassRole` enabled privilege escalation through the AWS CLI without requiring any IAM visibility or administrative permissions.

---

## Phase 1 — Console-Based Escalation (Blocked)

Observed behavior:

- `iam:ListRoles`, `iam:ListPolicies` → **AccessDenied**
    
- Lambda role dropdowns empty
    
- Role creation (`iam:CreateRole`) denied
    
- EC2 role selection restricted
    

### Outcome

> **Privilege escalation via PassRole was blocked at the console layer due to missing role enumeration permissions, demonstrating effective IAM hardening against browser‑based abuse.**

At this point, escalation **appeared impossible**.

---

## Phase 2 — Initial EC2 Activity by ops‑junior (Console)

- **ops‑junior** launched EC2 instances via console
    
- Could not explicitly select `AdminEC2Role`
    
- Instances launched successfully
    
- This caused **initial confusion** about:
    
    - Who launched which instance
        
    - Whether instances were privileged
        

This ambiguity mirrors real incident response challenges.

---

## Phase 3 — Attacker Pivot to CLI (ci‑helper)

With console escalation blocked, **ci‑helper pivoted to AWS CLI (PowerShell)** using existing automation access keys.

### Key Insight

The attacker did **not** need:

- Role listing
    
- IAM visibility
    
- Role creation
    

They only needed:

- The **name** of a privileged role
    
- `iam:PassRole`
    
- `ec2:RunInstances`
    

---

### Social Engineering Component

The role name **`AdminEC2Role`** was obtained via:

- Informal internal discussion
    
- Naming conventions
    
- Assumed trust in automation users
    

This was a **human failure**, not a technical one.

---

## Phase 4 — CLI Exploitation (Confirmed Escalation)

### Command Executed (AWS CLI)

``aws ec2 run-instances `   --image-id ami-0c02fb55956c7d316 `   --instance-type t3.micro `   --iam-instance-profile Name=AdminEC2Role `   --region us-east-1 `   --profile ci-helper``

### Result

- EC2 instance launched successfully
    
- `AdminEC2Role` attached
    
- Confirmed in CLI output:
    

`"IamInstanceProfile": {   "Arn": "arn:aws:iam::7xxxxxxxxxx5:instance-profile/AdminEC2Role" }`

🚨 **This proves that `ci-helper` independently launched a new administrator‑privileged EC2 instance.**

---

## Phase 5 — Asymmetric Control (Critical Finding)

Despite creating the instance, **ci-helper could NOT**:

- Terminate the instance
    
- Modify it
    
- Enumerate EC2 resources
    

All lifecycle actions failed with `AccessDenied`.

### Impact

> **ci-helper, a non‑privileged user, socially engineered information to launch persistent administrator‑privileged infrastructure, which they could not later manage.**

This is a **serious operational and security risk**.

---

## CloudTrail Verification

CloudTrail `RunInstances` events confirmed:

- Multiple launches by **ci-helper**
    
- Same source IP
    
- Same AMI
    
- Different timestamps
    
- Distinct access keys
    

This resolved all ambiguity and **proved independent escalation**, not reuse of ops‑junior’s instance.

---

## AMI Clarification (Critical Understanding)

- `ami-0c02fbxxxxxx7d316` is a **public Amazon Linux 2 AMI**
    
- AMIs are **templates**, not instances
    
- The same AMI can launch unlimited unrelated EC2 instances
    

> **Privilege escalation occurred via role attachment, not AMI reuse.**

---

## Security Impact Analysis

### What Went Wrong

- `iam:PassRole` granted without sufficient constraints
    
- No `iam:PassedToService` restriction
    
- Automation permissions exceeded lifecycle permissions
    
- Role name secrecy relied on as a control
    

### What Went Right

- Console hardening blocked browser‑based abuse
    
- IAM listing restrictions slowed discovery
    
- Admin intervention successfully contained impact
    

---

## Key Lessons Learned

1. `iam:PassRole` **is privilege escalation** when combined with compute
    
2. Console protections ≠ API protections
    
3. Role name secrecy is **not** a security boundary
    
4. Automation users are **high‑risk principals**
    
5. Creation permissions must align with lifecycle permissions
    

---

## Defensive Recommendations

- Restrict `iam:PassRole` with:
    
    - Explicit role ARNs
        
    - `iam:PassedToService`
        
- Align `RunInstances` with `TerminateInstances`
    
- Monitor CloudTrail for `PassRole + RunInstances`
    
- Treat CI/CD credentials as privileged assets
    
- Periodically audit orphaned and over‑trusted roles
    

---

## Final Conclusion

> **Even when IAM role visibility, listing, and creation are restricted, a user with `iam:PassRole` and workload execution permissions can escalate privileges through automation interfaces. Console‑based guardrails do not prevent CLI‑based role abuse.**

This lab demonstrates a **realistic, defensible, and commonly overlooked AWS privilege escalation path**, combining **technical misconfiguration** with **human trust failures** — exactly how real incidents occur.

The escalation was not enabled by excessive permissions alone, but by the combination of limited automation permissions and socially obtained operational knowledge.

---




