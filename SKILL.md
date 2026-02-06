# terraform-drift-check

Detect infrastructure drift between Terraform state and actual cloud resources.

## Description

`terraform-drift-check` helps DevOps teams identify when cloud infrastructure has drifted from its Terraform-defined state. It compares the Terraform state file against live resources in AWS, GCP, or Azure and reports discrepancies.

## Features

- **Multi-Cloud Support**: AWS, GCP, Azure
- **State Comparison**: Compare tfstate against live resources
- **Drift Reports**: Generate detailed drift reports in JSON/HTML
- **CI/CD Integration**: Exit codes for pipeline integration
- **Slack/Teams Alerts**: Optional webhook notifications

## Usage

### Check for Drift

```bash
python drift_check.py check \
  --state terraform.tfstate \
  --provider aws
```

### Generate Drift Report

```bash
python drift_check.py report \
  --state terraform.tfstate \
  --provider aws \
  --output drift-report.html
```

### Watch Mode (Continuous Monitoring)

```bash
python drift_check.py watch \
  --state terraform.tfstate \
  --provider aws \
  --interval 3600 \
  --webhook $SLACK_WEBHOOK_URL
```

## Configuration

Create a `drift_config.yaml` file:

```yaml
provider: aws
state_file: terraform.tfstate

# Resources to check
resources:
  - aws_instance
  - aws_security_group
  - aws_s3_bucket
  - aws_iam_role

# Resources to ignore
ignore:
  - aws_cloudwatch_log_group

# Alert settings
alerts:
  slack_webhook: ${SLACK_WEBHOOK_URL}
  threshold: warning  # info, warning, critical
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No drift detected |
| 1 | Drift detected |
| 2 | Provider authentication error |
| 3 | State file error |

## Requirements

- Python 3.8+
- boto3 (AWS)
- google-cloud-resource-manager (GCP)
- azure-mgmt-resource (Azure)
- PyYAML

## Installation

```bash
pip install -r requirements.txt
```

## License

MIT License
