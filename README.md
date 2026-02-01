🔐 AWS IAM Audit Access Architecture (Portfolio Project)
Overview

This project demonstrates a secure, enterprise-grade AWS auditing access model using IAM Roles and AWS STS.
It eliminates long-lived credentials and enforces least-privilege, time-bound access for auditors.

🎯 Goals

Provide full read-only visibility across the AWS account

Avoid sharing admin or persistent IAM credentials

Enable temporary, auditable access for security reviews

Follow AWS security best practices

🏗️ Architecture

IAM User (audit_user)

No direct AWS service permissions

Only allowed to call sts:AssumeRole

IAM Role (AuditReadOnlyRole)

Trusted by audit_user

Attached policy: ReadOnlyAccess

Used exclusively for auditing

AWS STS

Issues temporary credentials upon role assumption

Credentials expire automatically

🔄 Access Flow

Auditor authenticates using IAM user credentials

Auditor assumes AuditReadOnlyRole via AWS STS

AWS returns temporary credentials

Auditor performs read-only API calls

Credentials expire automatically

🔑 Credential Model
Type	Description
AccessKeyId	Temporary
SecretAccessKey	Temporary
SessionToken	Required
Expiration	Automatic

❗ No long-lived access keys are used for auditing.

🔐 Security Benefits

✔ Least privilege

✔ Time-limited access

✔ No shared admin accounts

✔ Full CloudTrail visibility

✔ Easy revocation (disable role trust)

🧪 Example CLI Usage
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/AuditReadOnlyRole \
  --role-session-name audit-session \
  --profile audit_user

📸 Validation Evidence

aws sts get-caller-identity

IAM user listing

Role trust policy

AccessDenied proof before trust

Successful STS session after trust

(Include screenshots)

💼 Why This Matters

This pattern is used by:

Security teams

External auditors

SOC2 / ISO 27001 audits

Enterprise AWS environments


⭐
“We don’t grant auditors permissions directly.
We issue temporary STS credentials via a trusted role, which limits blast radius and removes long-lived secrets.”
