#!/usr/bin/env python3
"""
terraform-drift-check: Detect infrastructure drift between Terraform state and cloud resources.

Compares Terraform state files against live cloud resources and reports discrepancies.
"""

import argparse
import sys
import os
import json
import yaml
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime


class Provider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class DriftSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class ResourceDrift:
    resource_type: str
    resource_id: str
    attribute: str
    expected_value: Any
    actual_value: Any
    severity: DriftSeverity
    
    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


@dataclass
class DriftReport:
    timestamp: str
    provider: str
    state_file: str
    total_resources: int
    drifted_resources: int
    drifts: List[ResourceDrift]
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'provider': self.provider,
            'state_file': self.state_file,
            'total_resources': self.total_resources,
            'drifted_resources': self.drifted_resources,
            'drifts': [d.to_dict() for d in self.drifts]
        }


def load_terraform_state(state_path: str) -> dict:
    """Load and parse Terraform state file."""
    if not os.path.exists(state_path):
        raise FileNotFoundError(f"State file not found: {state_path}")
    
    with open(state_path, 'r') as f:
        state = json.load(f)
    
    # Handle both v3 and v4 state formats
    if 'version' in state and state['version'] >= 4:
        return state
    else:
        # Convert v3 to v4-like structure
        return {
            'version': 4,
            'resources': state.get('modules', [{}])[0].get('resources', {})
        }


def extract_resources_from_state(state: dict) -> Dict[str, dict]:
    """Extract resource configurations from Terraform state."""
    resources = {}
    
    for resource in state.get('resources', []):
        resource_type = resource.get('type', '')
        resource_name = resource.get('name', '')
        
        for instance in resource.get('instances', []):
            attrs = instance.get('attributes', {})
            resource_id = attrs.get('id', f"{resource_type}.{resource_name}")
            
            resources[resource_id] = {
                'type': resource_type,
                'name': resource_name,
                'attributes': attrs
            }
    
    return resources


def get_aws_live_resources(resource_type: str, resource_ids: List[str]) -> Dict[str, dict]:
    """Fetch live resource state from AWS."""
    try:
        import boto3
    except ImportError:
        print("Error: boto3 not installed. Run: pip install boto3")
        sys.exit(3)
    
    live_resources = {}
    
    if resource_type == 'aws_instance':
        ec2 = boto3.client('ec2')
        try:
            response = ec2.describe_instances(InstanceIds=resource_ids)
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    live_resources[instance_id] = {
                        'instance_type': instance.get('InstanceType'),
                        'ami': instance.get('ImageId'),
                        'state': instance.get('State', {}).get('Name'),
                        'vpc_id': instance.get('VpcId'),
                        'subnet_id': instance.get('SubnetId'),
                        'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    }
        except Exception as e:
            print(f"Warning: Could not fetch EC2 instances: {e}")
    
    elif resource_type == 'aws_security_group':
        ec2 = boto3.client('ec2')
        try:
            response = ec2.describe_security_groups(GroupIds=resource_ids)
            for sg in response['SecurityGroups']:
                sg_id = sg['GroupId']
                live_resources[sg_id] = {
                    'name': sg.get('GroupName'),
                    'description': sg.get('Description'),
                    'vpc_id': sg.get('VpcId'),
                    'ingress_rules': len(sg.get('IpPermissions', [])),
                    'egress_rules': len(sg.get('IpPermissionsEgress', []))
                }
        except Exception as e:
            print(f"Warning: Could not fetch security groups: {e}")
    
    elif resource_type == 'aws_s3_bucket':
        s3 = boto3.client('s3')
        for bucket_name in resource_ids:
            try:
                # Get bucket location
                location = s3.get_bucket_location(Bucket=bucket_name)
                
                # Get versioning
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                
                live_resources[bucket_name] = {
                    'region': location.get('LocationConstraint', 'us-east-1'),
                    'versioning': versioning.get('Status', 'Disabled')
                }
            except Exception as e:
                print(f"Warning: Could not fetch bucket {bucket_name}: {e}")
    
    elif resource_type == 'aws_iam_role':
        iam = boto3.client('iam')
        for role_name in resource_ids:
            try:
                response = iam.get_role(RoleName=role_name)
                role = response['Role']
                live_resources[role_name] = {
                    'arn': role.get('Arn'),
                    'path': role.get('Path'),
                    'max_session_duration': role.get('MaxSessionDuration')
                }
            except Exception as e:
                print(f"Warning: Could not fetch IAM role {role_name}: {e}")
    
    return live_resources


def get_gcp_live_resources(resource_type: str, resource_ids: List[str], project_id: str) -> Dict[str, dict]:
    """Fetch live resource state from GCP."""
    try:
        from google.cloud import compute_v1
        from google.cloud import storage
    except ImportError:
        print("Error: google-cloud packages not installed.")
        sys.exit(3)
    
    live_resources = {}
    
    if resource_type == 'google_compute_instance':
        client = compute_v1.InstancesClient()
        # Implementation would go here
        pass
    
    return live_resources


def compare_resources(state_resources: Dict[str, dict], 
                     live_resources: Dict[str, dict],
                     resource_type: str) -> List[ResourceDrift]:
    """Compare state resources against live resources."""
    drifts = []
    
    # Define which attributes to compare for each resource type
    compare_attrs = {
        'aws_instance': ['instance_type', 'ami', 'vpc_id', 'subnet_id'],
        'aws_security_group': ['name', 'description', 'vpc_id'],
        'aws_s3_bucket': ['region', 'versioning'],
        'aws_iam_role': ['path', 'max_session_duration']
    }
    
    attrs_to_check = compare_attrs.get(resource_type, [])
    
    for resource_id, state_attrs in state_resources.items():
        if resource_id not in live_resources:
            drifts.append(ResourceDrift(
                resource_type=resource_type,
                resource_id=resource_id,
                attribute='existence',
                expected_value='exists',
                actual_value='missing',
                severity=DriftSeverity.CRITICAL
            ))
            continue
        
        live_attrs = live_resources[resource_id]
        
        for attr in attrs_to_check:
            state_val = state_attrs.get('attributes', {}).get(attr)
            live_val = live_attrs.get(attr)
            
            if state_val != live_val:
                # Determine severity based on attribute
                if attr in ['instance_type', 'ami']:
                    severity = DriftSeverity.CRITICAL
                elif attr in ['vpc_id', 'subnet_id']:
                    severity = DriftSeverity.WARNING
                else:
                    severity = DriftSeverity.INFO
                
                drifts.append(ResourceDrift(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    attribute=attr,
                    expected_value=state_val,
                    actual_value=live_val,
                    severity=severity
                ))
    
    return drifts


def check_drift(state_path: str, provider: Provider, 
               resource_types: List[str] = None,
               ignore_types: List[str] = None) -> DriftReport:
    """Check for drift between Terraform state and live resources."""
    state = load_terraform_state(state_path)
    state_resources = extract_resources_from_state(state)
    
    # Default resource types to check
    if resource_types is None:
        if provider == Provider.AWS:
            resource_types = ['aws_instance', 'aws_security_group', 'aws_s3_bucket', 'aws_iam_role']
        elif provider == Provider.GCP:
            resource_types = ['google_compute_instance', 'google_storage_bucket']
        else:
            resource_types = []
    
    ignore_types = ignore_types or []
    resource_types = [rt for rt in resource_types if rt not in ignore_types]
    
    all_drifts = []
    total_resources = 0
    
    for resource_type in resource_types:
        # Filter resources by type
        typed_resources = {
            rid: rdata for rid, rdata in state_resources.items()
            if rdata.get('type') == resource_type
        }
        
        if not typed_resources:
            continue
        
        total_resources += len(typed_resources)
        resource_ids = list(typed_resources.keys())
        
        # Fetch live resources
        if provider == Provider.AWS:
            live_resources = get_aws_live_resources(resource_type, resource_ids)
        elif provider == Provider.GCP:
            live_resources = get_gcp_live_resources(resource_type, resource_ids, '')
        else:
            live_resources = {}
        
        # Compare
        drifts = compare_resources(typed_resources, live_resources, resource_type)
        all_drifts.extend(drifts)
    
    # Count unique drifted resources
    drifted_ids = set(d.resource_id for d in all_drifts)
    
    return DriftReport(
        timestamp=datetime.utcnow().isoformat(),
        provider=provider.value,
        state_file=state_path,
        total_resources=total_resources,
        drifted_resources=len(drifted_ids),
        drifts=all_drifts
    )


def print_drift_report(report: DriftReport):
    """Print drift report to console."""
    print(f"\n{'='*60}")
    print(f"Terraform Drift Report")
    print(f"{'='*60}")
    print(f"Timestamp: {report.timestamp}")
    print(f"Provider: {report.provider}")
    print(f"State File: {report.state_file}")
    print(f"Total Resources: {report.total_resources}")
    print(f"Drifted Resources: {report.drifted_resources}")
    print(f"{'='*60}\n")
    
    if not report.drifts:
        print("✅ No drift detected!")
        return
    
    # Group by severity
    critical = [d for d in report.drifts if d.severity == DriftSeverity.CRITICAL]
    warning = [d for d in report.drifts if d.severity == DriftSeverity.WARNING]
    info = [d for d in report.drifts if d.severity == DriftSeverity.INFO]
    
    if critical:
        print("🔴 CRITICAL DRIFT:")
        for d in critical:
            print(f"  [{d.resource_type}] {d.resource_id}")
            print(f"    {d.attribute}: {d.expected_value} → {d.actual_value}")
        print()
    
    if warning:
        print("🟡 WARNING DRIFT:")
        for d in warning:
            print(f"  [{d.resource_type}] {d.resource_id}")
            print(f"    {d.attribute}: {d.expected_value} → {d.actual_value}")
        print()
    
    if info:
        print("🔵 INFO DRIFT:")
        for d in info:
            print(f"  [{d.resource_type}] {d.resource_id}")
            print(f"    {d.attribute}: {d.expected_value} → {d.actual_value}")
        print()


def generate_html_report(report: DriftReport, output_path: str):
    """Generate HTML drift report."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Terraform Drift Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f5f5f5; padding: 15px; border-radius: 8px; flex: 1; }}
        .stat-value {{ font-size: 24px; font-weight: bold; }}
        .drift {{ border: 1px solid #ddd; border-radius: 8px; margin: 10px 0; padding: 15px; }}
        .drift.critical {{ border-left: 4px solid #e74c3c; }}
        .drift.warning {{ border-left: 4px solid #f39c12; }}
        .drift.info {{ border-left: 4px solid #3498db; }}
        .resource-id {{ font-family: monospace; background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }}
        .change {{ display: flex; gap: 10px; margin-top: 10px; }}
        .expected {{ color: #e74c3c; }}
        .actual {{ color: #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Terraform Drift Report</h1>
        <p>Generated: {report.timestamp}</p>
        <p>Provider: {report.provider} | State: {report.state_file}</p>
    </div>
    
    <div class="stats">
        <div class="stat">
            <div class="stat-value">{report.total_resources}</div>
            <div>Total Resources</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report.drifted_resources}</div>
            <div>Drifted Resources</div>
        </div>
        <div class="stat">
            <div class="stat-value">{len(report.drifts)}</div>
            <div>Total Drifts</div>
        </div>
    </div>
    
    <h2>Drift Details</h2>
"""
    
    for drift in report.drifts:
        severity_class = drift.severity.value
        html += f"""
    <div class="drift {severity_class}">
        <strong>[{drift.resource_type}]</strong> <span class="resource-id">{drift.resource_id}</span>
        <div class="change">
            <span><strong>{drift.attribute}:</strong></span>
            <span class="expected">{drift.expected_value}</span>
            <span>→</span>
            <span class="actual">{drift.actual_value}</span>
        </div>
    </div>
"""
    
    html += """
</body>
</html>
"""
    
    with open(output_path, 'w') as f:
        f.write(html)
    
    print(f"HTML report written to: {output_path}")


def send_webhook_alert(report: DriftReport, webhook_url: str):
    """Send drift alert to webhook (Slack/Teams)."""
    try:
        import requests
    except ImportError:
        print("Warning: requests not installed, skipping webhook")
        return
    
    if not report.drifts:
        return
    
    critical_count = len([d for d in report.drifts if d.severity == DriftSeverity.CRITICAL])
    warning_count = len([d for d in report.drifts if d.severity == DriftSeverity.WARNING])
    
    # Slack-compatible payload
    payload = {
        "text": f"🚨 Terraform Drift Detected",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Terraform Drift Detected"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Provider:* {report.provider}"},
                    {"type": "mrkdwn", "text": f"*State File:* {report.state_file}"},
                    {"type": "mrkdwn", "text": f"*Critical:* {critical_count}"},
                    {"type": "mrkdwn", "text": f"*Warning:* {warning_count}"}
                ]
            }
        ]
    }
    
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        print(f"Warning: Failed to send webhook: {e}")


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Expand environment variables
    if 'alerts' in config and 'slack_webhook' in config['alerts']:
        webhook = config['alerts']['slack_webhook']
        if webhook.startswith('${') and webhook.endswith('}'):
            env_var = webhook[2:-1]
            config['alerts']['slack_webhook'] = os.environ.get(env_var, '')
    
    return config


def cmd_check(args):
    """Handle check command."""
    try:
        provider = Provider(args.provider)
        report = check_drift(args.state, provider)
        print_drift_report(report)
        
        if report.drifts:
            return 1
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 3
    except Exception as e:
        print(f"Error: {e}")
        return 2


def cmd_report(args):
    """Handle report command."""
    try:
        provider = Provider(args.provider)
        report = check_drift(args.state, provider)
        
        if args.output.endswith('.html'):
            generate_html_report(report, args.output)
        else:
            with open(args.output, 'w') as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"JSON report written to: {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 2


def cmd_watch(args):
    """Handle watch command."""
    try:
        provider = Provider(args.provider)
        interval = args.interval
        webhook = args.webhook
        
        print(f"Starting drift watch (interval: {interval}s)")
        print("Press Ctrl+C to stop\n")
        
        while True:
            report = check_drift(args.state, provider)
            print_drift_report(report)
            
            if webhook and report.drifts:
                send_webhook_alert(report, webhook)
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nWatch stopped")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 2


def main():
    parser = argparse.ArgumentParser(
        description='Detect infrastructure drift between Terraform state and cloud resources'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check for drift')
    check_parser.add_argument('--state', '-s', required=True, help='Path to terraform.tfstate')
    check_parser.add_argument('--provider', '-p', required=True, choices=['aws', 'gcp', 'azure'])
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate drift report')
    report_parser.add_argument('--state', '-s', required=True, help='Path to terraform.tfstate')
    report_parser.add_argument('--provider', '-p', required=True, choices=['aws', 'gcp', 'azure'])
    report_parser.add_argument('--output', '-o', required=True, help='Output file (json or html)')
    
    # Watch command
    watch_parser = subparsers.add_parser('watch', help='Continuous drift monitoring')
    watch_parser.add_argument('--state', '-s', required=True, help='Path to terraform.tfstate')
    watch_parser.add_argument('--provider', '-p', required=True, choices=['aws', 'gcp', 'azure'])
    watch_parser.add_argument('--interval', '-i', type=int, default=3600, help='Check interval in seconds')
    watch_parser.add_argument('--webhook', '-w', help='Slack/Teams webhook URL for alerts')
    
    args = parser.parse_args()
    
    if args.command == 'check':
        sys.exit(cmd_check(args))
    elif args.command == 'report':
        sys.exit(cmd_report(args))
    elif args.command == 'watch':
        sys.exit(cmd_watch(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    main()
