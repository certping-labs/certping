# AWS discovery

CertPing finds ACM certificates in every enabled region of an AWS account, or in every account
of your AWS Organization. Discovery is read-only: these roles cannot import, change or delete
anything. Deploying certificates to AWS uses a separate deployment credential.

## One account (no templates needed)

Give the identity the agent runs as these permissions: `acm:ListCertificates`,
`acm:DescribeCertificate`, `acm:GetCertificate`, `account:ListRegions`. Then select
**Connect AWS** on the **Certificate Discovery** page. If the account is not in an Organization (or the agent may not list it),
CertPing scans just that account.

## Whole organization

1. The agent signs in to the hub account (its own identity, or the `CertPingDiscoveryHub` role).
2. It lists the organization's active accounts.
3. In each account it assumes `CertPingDiscoveryReadOnly`.
4. It lists the account's enabled regions and reads ACM in each one.

One broken account or region is skipped and logged. The rest of the scan still finishes.

## Set up

1. In the management account (or a delegated administrator), create a stack from
   `hub-role.yaml`. Pass the ARN the agent runs as. Skip this if the agent already runs in that
   account and you give its identity the same permissions.
2. Create a service-managed StackSet from `member-role.yaml` targeting your organization root (or
   the OUs you want), with auto-deployment on so new accounts get the role. Set `HubAccountId` to
   the hub account. StackSets do not deploy to the management account itself; the hub identity
   reads that account directly.
3. In CertPing, open **Certificate Discovery** and select **Connect AWS**. Choose how the agent
   signs in, then select **Connect and scan**.

The form has three optional fields:

| Field | Effect |
| --- | --- |
| Only these accounts | Scans a fixed list instead of listing the organization. Use it when the agent cannot call `organizations:ListAccounts`. |
| Only these regions | Skips region listing. |
| External ID | Must match the `ExternalId` parameter on the member role. |

## Permissions used

| Where | Actions |
| --- | --- |
| Hub | `organizations:ListAccounts`, `sts:AssumeRole` on the member role, plus the member actions for its own account |
| Each member | `acm:ListCertificates`, `acm:DescribeCertificate`, `acm:GetCertificate`, `account:ListRegions` |

`acm:GetCertificate` returns only the public certificate, never the private key. It is used to
read the key type when ACM leaves it blank.
