# Azure Privileged Access Drift Detector

This tool detects changes (drift) in privileged access assignments across Azure RBAC and Microsoft Entra ID. It is designed for security teams to monitor for unexpected or unauthorized grants of high-impact permissions.

It works by taking periodic snapshots of role assignments and comparing the current state against the last known good state, producing a clear report of what has been added, removed, or changed.

## What It Does
- Scans Azure RBAC role assignments across one or more subscriptions.
- Scans Microsoft Entra ID for members of privileged directory roles.
- Compares the current state to the most recent previous snapshot.
- Generates human-readable and machine-readable reports detailing the drift.
- Can optionally exit with a specific error code if high-risk changes are detected, making it suitable for automation.
- Uses the Azure CLI for data collection, requiring no complex SDKs or separate authentication.

## What It Does Not Do
- **It does not manage or modify any access.** It is a read-only tool.
- **It does not check non-privileged roles.** It is focused on a configurable list of privileged roles to reduce noise.
- **It does not analyze permissions inside groups.** If a role is assigned to a group, the tool reports the assignment to the group, but not the group's membership.

## Prerequisites
1.  **Python 3.11+**
2.  **Azure CLI:** The tool calls `az` commands directly. You must have it installed and in your system's PATH.
3.  **Authenticated Azure CLI:** You must be logged into an Azure account by running `az login`.

## Permissions
- **Azure RBAC:** The identity running the scan (your logged-in `az` user) needs at a minimum the built-in `Reader` role on each subscription you intend to scan. This allows it to list role assignments.
- **Microsoft Entra ID (Optional):** To scan Entra directory roles, the identity needs `Directory.Read.All` permission in Microsoft Graph. If these permissions are not granted, the tool will gracefully skip the Entra scan and note it in the report.

## Installation
1.  Clone the repository.
2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
The script is run from the command line.

**Basic RBAC Scan (all accessible subscriptions):**
```bash
python privileged_access_drift.py
```

**Scan a Specific Set of Subscriptions:**
```bash
python privileged_access_drift.py --subscriptions "sub-id-1,sub-id-2"
```

**Include Entra ID Scan (if permissions allow):**
```bash
python privileged_access_drift.py --tenant "your-tenant-id.onmicrosoft.com"
```

**Full Example:**
```bash
python privileged_access_drift.py --tenant "your-tenant-id.onmicrosoft.com" --subscriptions "sub-id-1" --verbose --fail-on-high false
```

### Command-Line Arguments
- `--config PATH`: Path to a `config.yaml` file. Defaults to `./config.yaml`.
- `--snapshot-dir PATH`: Directory to store snapshots. Defaults to `./snapshots`.
- `--out-dir PATH`: Directory for reports. Defaults to `./output`.
- `--subscriptions sub1,sub2,...`: Comma-separated list of subscription IDs to scan. If omitted, scans all accessible subscriptions.
- `--tenant TENANT_ID`: Your tenant ID or domain. Required for Entra scans.
- `--teams-summary`: If set, generates a concise summary for easy pasting into a Teams message.
- `--fail-on-high`: If `true` (the default), exits with code `2` if new high-risk roles are detected.
- `--no-entra`: Explicitly disable the Entra ID scan.
- `--verbose`: Enable detailed logging to the console.

## Customization
To customize the tool's behavior, copy `config.yaml.example` to `config.yaml` and edit it.

**Key settings you can change:**
- `privileged_roles`: Add or remove RBAC and Entra roles to be considered in scope for scanning.
- `risk`: Define which roles are considered "high-risk" and whether to flag all guest assignments as high-risk.

**Warning:** The `.gitignore` file is configured to ignore `config.yaml`. Do not commit your `config.yaml` file to version control, as it may contain internal naming conventions.

## Outputs
The tool generates snapshots and reports in the specified directories.

- `snapshots/snapshot_YYYYMMDD_HHMMSS.json`: A JSON file containing the raw data collected during a run. This is the state used for comparison in the next run.
- `output/diff_report.md`: A Markdown report detailing all changes since the last snapshot.
- `output/diff_report.csv`: A CSV report suitable for importing into other tools or spreadsheets.
- `output/teams_summary.txt`: (Optional) A short text file with a summary of high-risk changes.

## Limitations and Troubleshooting
- **Graph API 403 Forbidden:** If you see errors related to Graph permissions, it means the identity you are using does not have `Directory.Read.All`. The tool will skip the Entra scan but should still complete the RBAC scan.
- **Missing `principalName`:** In some rare cases, the `principalName` for a role assignment may not be returned by the API. The tool will use the `principalId` in these cases.
- **Group Membership:** The tool does not recursively resolve group memberships. An assignment to a group is reported as a single assignment.

