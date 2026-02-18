# -*- coding: utf-8 -*-
"""
Azure Privileged Access Drift Detector

Detects changes in privileged access assignments across Azure RBAC and Microsoft Entra ID.
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import yaml

TOOL_VERSION = "1.0.0"

# --- Utility Functions ---

def setup_logging(verbose):
    """Sets up logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def run_az_command(command, tenant_id=None):
    """Runs an Azure CLI command and returns the JSON output."""
    try:
        if tenant_id:
            command.extend(["--tenant", tenant_id])
        logging.debug(f"Running command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except FileNotFoundError:
        logging.error("Azure CLI not found. Please ensure 'az' is installed and in your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Azure CLI command failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        return None
    except json.JSONDecodeError:
        logging.error("Failed to parse JSON output from Azure CLI.")
        return None

def get_az_version():
    """Gets the Azure CLI version."""
    try:
        result = subprocess.run(["az", "version"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unknown"

# --- Data Collection ---

def collect_rbac_assignments(subscription_ids):
    """Collects privileged RBAC role assignments for the given subscriptions."""
    all_assignments = []
    
    current_sub = run_az_command(["az", "account", "show"])
    if not current_sub:
        logging.error("Failed to get current subscription. Is `az login` complete?")
        return [], ["Failed to get current subscription."]

    original_subscription_id = current_sub.get("id")
    
    for sub_id in subscription_ids:
        logging.info(f"Scanning subscription: {sub_id}")
        if run_az_command(["az", "account", "set", "--subscription", sub_id]) is None:
            logging.warning(f"Could not switch to subscription {sub_id}. Skipping.")
            continue
            
        assignments = run_az_command(["az", "role", "assignment", "list", "--all"])
        if assignments:
            for a in assignments:
                all_assignments.append({
                    "source": "azure_rbac",
                    "subscriptionId": sub_id,
                    "subscriptionName": "N/A", # This would require another API call
                    "scope": a.get("scope"),
                    "roleDefinitionName": a.get("roleDefinitionName"),
                    "roleDefinitionId": a.get("roleDefinitionId"),
                    "principalId": a.get("principalId"),
                    "principalName": a.get("principalName"),
                    "principalType": a.get("principalType"),
                    "createdOn": a.get("createdOn"),
                })

    # Restore original subscription
    run_az_command(["az", "account", "set", "--subscription", original_subscription_id])
    return all_assignments, []

def collect_entra_roles(tenant_id, role_names):
    """Collects members of privileged Entra ID roles."""
    if not tenant_id:
        return [], ["Entra scanning skipped: --tenant not provided."]
    
    logging.info("Starting Entra ID role collection.")
    roles_data = run_az_command(["az", "rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/directoryRoles"], tenant_id=tenant_id)
    if not roles_data:
        return [], ["Failed to get Entra roles. Check Graph permissions (Directory.Read.All)."]
    
    privileged_roles = {role['displayName']: role['id'] for role in roles_data.get('value', []) if role['displayName'] in role_names}
    
    all_members = []
    errors = []
    for role_name, role_id in privileged_roles.items():
        logging.info(f"Getting members for Entra role: {role_name}")
        members_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName"
        members_data = run_az_command(["az", "rest", "--method", "get", "--url", members_url], tenant_id=tenant_id)
        
        if members_data and 'value' in members_data:
            for member in members_data['value']:
                all_members.append({
                    "source": "entra",
                    "roleName": role_name,
                    "roleId": role_id,
                    "principalId": member.get("id"),
                    "principalName": member.get("displayName") or member.get("userPrincipalName"),
                    "principalType": "user", # Best effort
                })
        else:
            errors.append(f"Could not retrieve members for Entra role: {role_name}")
            
    return all_members, errors

# --- Snapshot and Diff Logic ---

def load_latest_snapshot(snapshot_dir):
    """Loads the most recent snapshot file."""
    snapshot_files = sorted(Path(snapshot_dir).glob("snapshot_*.json"), reverse=True)
    if not snapshot_files:
        return None
    
    logging.info(f"Loading previous snapshot: {snapshot_files[0]}")
    with open(snapshot_files[0], 'r') as f:
        return json.load(f)

def create_assignment_key(assignment, config):
    """Creates a stable key for a role assignment."""
    use_ids = config['matching']['use_role_ids_when_available']
    norm_scopes = config['matching']['normalize_scopes']

    if assignment['source'] == 'azure_rbac':
        role_key = assignment.get('roleDefinitionId') if use_ids and assignment.get('roleDefinitionId') else assignment.get('roleDefinitionName')
        scope = assignment.get('scope') or ''
        if norm_scopes:
            scope = scope.lower().strip('/')
        return (assignment['principalId'], role_key, scope, assignment['subscriptionId'])
    elif assignment['source'] == 'entra':
        role_key = assignment.get('roleId') if use_ids and assignment.get('roleId') else assignment.get('roleName')
        return (assignment['principalId'], role_key)
    return None

def diff_snapshots(current_snapshot, previous_snapshot, config):
    """Compares two snapshots and returns the differences."""
    if not previous_snapshot:
        logging.warning("No previous snapshot found. Reporting all current assignments as 'ADDED'.")
        previous_data = {'azure_rbac': [], 'entra': []}
    else:
        previous_data = previous_snapshot.get('data', {})

    current_data = current_snapshot.get('data', {})
    
    # Create sets for easy comparison
    prev_rbac_keys = {create_assignment_key(a, config): a for a in previous_data.get('azure_rbac', [])}
    curr_rbac_keys = {create_assignment_key(a, config): a for a in current_data.get('azure_rbac', [])}
    prev_entra_keys = {create_assignment_key(a, config): a for a in previous_data.get('entra', [])}
    curr_entra_keys = {create_assignment_key(a, config): a for a in current_data.get('entra', [])}

    diff = {
        'added': [a for k, a in curr_rbac_keys.items() if k not in prev_rbac_keys] + 
                 [a for k, a in curr_entra_keys.items() if k not in prev_entra_keys],
        'removed': [a for k, a in prev_rbac_keys.items() if k not in curr_rbac_keys] +
                   [a for k, a in prev_entra_keys.items() if k not in curr_entra_keys],
        'scope_change': [] # Basic implementation, can be enhanced
    }
    return diff

# --- Reporting ---

def get_risk(change, config):
    """Determines the risk level of a change."""
    is_guest = "guest" in (change.get('principalType') or "").lower()
    
    if config['risk']['include_guests_as_high'] and is_guest:
        return "high"
        
    if change['source'] == 'azure_rbac':
        if change['roleDefinitionName'] in config['risk']['high_rbac_roles']:
            return "high"
    elif change['source'] == 'entra':
        if change['roleName'] in config['risk']['high_entra_roles']:
            return "high"
            
    return "medium"

def write_reports(diff, config, out_dir, teams_summary_flag):
    """Writes the drift reports."""
    # Create output directory if it doesn't exist
    os.makedirs(out_dir, exist_ok=True)
    
    high_risk_additions = []

    # MD Report
    with open(Path(out_dir) / "diff_report.md", "w") as f:
        f.write("# Privileged Access Drift Report

")
        # Summary
        f.write("## Summary
")
        f.write(f"- Added: {len(diff['added'])}
")
        f.write(f"- Removed: {len(diff['removed'])}

")
        
        # Added
        f.write("## Added Assignments
")
        if diff['added']:
            f.write("| Risk | Source | Role | Principal | Scope/Subscription |
")
            f.write("|------|--------|------|-----------|--------------------|
")
            for item in diff['added']:
                risk = get_risk(item, config)
                if risk == "high":
                    high_risk_additions.append(item)
                scope = item.get('scope') or item.get('subscriptionName') or "N/A"
                f.write(f"| {risk} | {item['source']} | {item.get('roleDefinitionName') or item.get('roleName')} | {item['principalName']} | `{scope}` |
")
        else:
            f.write("No new assignments detected.
")

    # CSV Report
    if config['output']['write_csv']:
        import csv
        csv_path = Path(out_dir) / "diff_report.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "category", "change_type", "risk", "roleName", "roleId",
                "principalName", "principalId", "principalType", "scope",
                "subscriptionId", "subscriptionName", "timestamp"
            ])
            
            # Write added items
            for item in diff['added']:
                risk = get_risk(item, config)
                writer.writerow([
                    item['source'], 'added', risk,
                    item.get('roleDefinitionName') or item.get('roleName'),
                    item.get('roleDefinitionId') or item.get('roleId'),
                    item.get('principalName'), item.get('principalId'),
                    item.get('principalType'), item.get('scope'),
                    item.get('subscriptionId'), item.get('subscriptionName'),
                    datetime.datetime.utcnow().isoformat()
                ])

            # Write removed items
            for item in diff['removed']:
                risk = get_risk(item, config)
                writer.writerow([
                    item['source'], 'removed', risk,
                    item.get('roleDefinitionName') or item.get('roleName'),
                    item.get('roleDefinitionId') or item.get('roleId'),
                    item.get('principalName'), item.get('principalId'),
                    item.get('principalType'), item.get('scope'),
                    item.get('subscriptionId'), item.get('subscriptionName'),
                    datetime.datetime.utcnow().isoformat()
                ])
        logging.info(f"CSV report written to {csv_path}")

    # Teams Summary
    if teams_summary_flag:
        with open(Path(out_dir) / "teams_summary.txt", "w") as f:
            if high_risk_additions:
                f.write("**High-Risk Privileged Access Additions Detected!**

")
                for item in high_risk_additions:
                    f.write(f"- **Role:** {item.get('roleDefinitionName') or item.get('roleName')}
")
                    f.write(f"  - **Principal:** {item['principalName']}
")
                    f.write(f"  - **Scope:** {item.get('scope') or 'Entra'}

")
            else:
                 f.write("No high-risk additions detected in this run.
")

    return high_risk_additions

# --- Main Logic ---

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Azure Privileged Access Drift Detector")
    parser.add_argument("--config", default="config.yaml", help="Path to config file.")
    parser.add_argument("--snapshot-dir", default="snapshots", help="Directory for snapshots.")
    parser.add_argument("--out-dir", default="output", help="Directory for reports.")
    parser.add_argument("--subscriptions", help="Comma-separated list of subscription IDs.")
    parser.add_argument("--tenant", help="Tenant ID for Entra scans.")
    parser.add_argument("--teams-summary", action="store_true", help="Generate a Teams summary.")
    parser.add_argument("--fail-on-high", type=lambda x: str(x).lower() == 'true', default=True, help="Exit with code 2 on high-risk additions.")
    parser.add_argument("--no-entra", action="store_true", help="Skip Entra ID collection.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    # Load config
    config_path = Path(args.config)
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    else:
        with open('config.yaml.example', 'r') as f:
            config = yaml.safe_load(f)
        logging.warning("config.yaml not found, using defaults from config.yaml.example.")

    # Determine subscriptions to scan
    if args.subscriptions:
        subscription_ids = [s.strip() for s in args.subscriptions.split(',')]
    else:
        accounts = run_az_command(["az", "account", "list", "--output", "json"])
        if not accounts:
            logging.error("Could not list subscriptions.")
            sys.exit(1)
        subscription_ids = [sub['id'] for sub in accounts if sub['state'] == 'Enabled']

    # Data Collection
    rbac_assignments, rbac_errors = collect_rbac_assignments(subscription_ids)
    
    entra_members, entra_errors = [], []
    if not args.no_entra:
        entra_members, entra_errors = collect_entra_roles(args.tenant, config['privileged_roles']['entra'])
        
    # Create current snapshot
    current_snapshot = {
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "tool_version": TOOL_VERSION,
            "az_version": get_az_version(),
            "tenant": args.tenant,
        },
        "data": {
            "azure_rbac": rbac_assignments,
            "entra": entra_members,
            "errors": rbac_errors + entra_errors,
        }
    }

    # Save current snapshot
    os.makedirs(args.snapshot_dir, exist_ok=True)
    snapshot_filename = f"snapshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(Path(args.snapshot_dir) / snapshot_filename, 'w') as f:
        json.dump(current_snapshot, f, indent=2)

    # Diff and report
    previous_snapshot = load_latest_snapshot(args.snapshot_dir)
    diff = diff_snapshots(current_snapshot, previous_snapshot, config)
    
    high_risk_additions = write_reports(diff, config, args.out_dir, args.teams_summary)
    
    logging.info("Drift detection complete.")
    
    # Exit code logic
    if args.fail_on_high and high_risk_additions:
        logging.warning(f"Detected {len(high_risk_additions)} high-risk additions. Exiting with code 2.")
        sys.exit(2)
        
    sys.exit(0)

if __name__ == "__main__":
    main()
