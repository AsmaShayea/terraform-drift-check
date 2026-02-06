# terraform-drift-check

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Detect infrastructure drift between Terraform state and actual cloud resources.

## The Problem

Infrastructure drift is a silent killer of reliability:

- **Manual changes**: Someone SSH'd into a server and changed something
- **Console edits**: Quick fixes made in AWS/GCP/Azure console
- **Forgotten resources**: Resources created outside Terraform
- **State corruption**: Terraform state doesn't match reality

`terraform-drift-check` catches these issues before they cause outages.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Check for drift
python drift_check.py check \
  --state terraform.tfstate \
  --provider aws

# Generate HTML report
python drift_check.py report \
  --state terraform.tfstate \
  --provider aws \
  --output drift-report.html
```

## Features

### Multi-Cloud Support

| Provider | Status |
|----------|--------|
| AWS | ✅ Full support |
| GCP | ✅ Full support |
| Azure | 🚧 Coming soon |

### Supported AWS Resources

- `aws_instance` - EC2 instances
- `aws_security_group` - Security groups
- `aws_s3_bucket` - S3 buckets
- `aws_iam_role` - IAM roles
- More coming soon...

### Drift Severity Levels

| Level | Description |
|-------|-------------|
| 🔴 CRITICAL | Resource missing or major config change |
| 🟡 WARNING | Network/security configuration changed |
| 🔵 INFO | Minor attribute differences |

### Continuous Monitoring

Run in watch mode for continuous drift detection:

```bash
python drift_check.py watch \
  --state terraform.tfstate \
  --provider aws \
  --interval 3600 \
  --webhook $SLACK_WEBHOOK_URL
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Drift Check
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Check for drift
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          python drift_check.py check \
            --state terraform.tfstate \
            --provider aws
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No drift detected |
| 1 | Drift detected |
| 2 | Provider authentication error |
| 3 | State file error |

## Configuration

Create a `drift_config.yaml` for advanced configuration:

```yaml
provider: aws
state_file: terraform.tfstate

resources:
  - aws_instance
  - aws_security_group
  - aws_s3_bucket

ignore:
  - aws_cloudwatch_log_group

alerts:
  slack_webhook: ${SLACK_WEBHOOK_URL}
  threshold: warning
```

## Installation

```bash
git clone https://github.com/devtools/terraform-drift-check.git
cd terraform-drift-check
pip install -r requirements.txt
```

## Authentication

### AWS

```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### GCP

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GOOGLE_CLOUD_PROJECT=your-project-id
```

## Contributing

Contributions welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE) for details.
