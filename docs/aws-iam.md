# AWS IAM connector

Athena's AWS IAM connector inventories authorization evidence without changing AWS. It uses the
standard AWS credential provider chain and never requests or stores secret access-key material.

## Minimum collector policy

Attach a policy equivalent to the following to a dedicated collector role. Restrict role assumption
through the role trust policy and your normal AWS controls.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AthenaIamInventory",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:GetRole",
        "iam:ListAccessKeys",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Configuration

Athena supports AWS environment credentials, shared configuration files, workload roles, and
instance roles through boto3. A named local profile is optional.

```dotenv
ATHENA_AWS_PROFILE=athena-read-only
ATHENA_AWS_REGION=us-east-1
ATHENA_AWS_ENABLED=true
```

`ATHENA_AWS_ENABLED` controls inclusion in the continuous-monitoring pipeline. The explicit command
can be run independently:

```bash
python -m athena.cli sync-aws-iam
```

## Collected evidence

- IAM users, groups, group membership, and roles;
- role trust-policy documents and permission-boundary metadata;
- role owner tags (`Owner` or `athena:owner`) plus AWS-reported last-used time and region;
- customer-managed and AWS-managed policies plus inline policies;
- allowed actions and resource ARN patterns;
- access-key status, creation time, and calculated age without secret key material;
- paginated account inventory and per-user access-key inventory;
- content fingerprints, unchanged-snapshot detection, revocation detection, and audit events.

The connector status appears in `GET /v1/connectors` as `aws_iam` with the AWS account ID as its
scope. Cached endpoint details expose counts and a fingerprint, not policy payloads.

## Authorization limitations

An IAM inventory is not the same as an AWS authorization simulation. Athena records Allow statements
and their direct, group, or role lineage, but marks that lineage incomplete. The initial connector
does not resolve:

- explicit Deny precedence;
- permissions boundaries;
- AWS Organizations service-control policies;
- resource-based or session policies;
- policy variables, `NotAction`, or `NotResource`; or
- runtime evaluation of conditions and indirect role-assumption chains.

These limitations are stored on every policy-derived grant so downstream policy, risk, and audit
views cannot mistake observed policy evidence for a definitive effective-access decision.

Role tags are reduced to the recognized owner value during normalization. The machine-identity API
does not expose raw tag collections, trust policies, role responses, access-key identifiers, or
credential material. AWS role last-used data is service-provided evidence and can be absent or
limited by AWS retention; Athena leaves that absence visible instead of inferring activity.
