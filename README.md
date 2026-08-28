# Tenable → Datadog Cloud Security vulnerability import (custom Agent check)

This is a custom Datadog Agent check that:

1. Pulls open vulnerability findings from **Tenable Vulnerability Management
   (Tenable.io)** using [pyTenable](https://developer.tenable.com/docs/introduction-to-pytenable)'s
   vulnerability export API (`tio.exports.vulns()`, a wrapper around
   [`/vulns/export`](https://developer.tenable.com/reference/navigate)).
2. Groups findings by asset and converts them into **CycloneDX 1.5** BOMs.
3. Submits each BOM to Datadog's vulnerability import endpoint:
   `POST /api/v2/security/vulnerabilities`.

## Tenable.io vs. Tenable Security Center

This check supports both deployments via `tenable_platform` in `conf.yaml`:

- **`tenable_io`** (default) — uses pyTenable's `TenableIO` client and the
  vulnerability export API (`tio.exports.vulns()`). Auth is `tenable_access_key`
  / `tenable_secret_key`.
- **`tenable_sc`** — uses pyTenable's `TenableSC` client against your on-prem
  Security Center instance (`sc.analysis.vulns()`, the `Analysis` API's
  `vulndetails` tool with `sourceType='cumulative'`, which returns active/
  unmitigated instances only — mitigated vulns are excluded automatically, so
  no separate "state" filter is needed). Auth is either `sc_access_key`/
  `sc_secret_key` (SC 5.13+) or `sc_username`/`sc_password` for older
  instances. Set `sc_host` (and `sc_port` if not 443).

Both paths are normalized into the same internal shape before being turned
into CycloneDX, so everything downstream (batching, submission, cadence)
behaves identically regardless of which platform you're on.

### Things that differ with Security Center

- **No stable asset UUID.** Unlike Tenable.io, Security Center doesn't expose
  a persistent per-asset UUID in analysis results. The check builds an asset
  key from IP + repository ID instead. This is stable as long as the host's
  IP and repository don't change, but re-IP'd hosts will show up as a "new"
  asset in Datadog. Datadog's spec doesn't require BOM-ref consistency across
  imports, so this only matters for how findings are grouped, not for whether
  the import succeeds.
- **No CWE list by default.** Security Center's analysis output doesn't
  include a structured CWE field the way Tenable.io's plugin object does; the
  check parses CWE identifiers out of the `xref` field when present, but
  coverage will be less complete.
- **Filter syntax varies by SC version.** The `lastSeen` range filter used for
  differential exports (`"<start>:<end>"` as epoch seconds) is the commonly
  documented pattern, but Tenable has changed analysis filter behavior across
  Security Center releases. Run `datadog-agent check tenable_vulns` after
  setup and confirm you're getting the expected number of findings before
  relying on this in production — adjust the filter tuple in
  `_export_sc_vulns()` if your version needs different syntax.
- **TLS.** On-prem Security Center instances often use self-signed
  certificates. Prefer installing the cert in the Agent's trust store over
  setting `sc_ssl_verify: false`.

## Cloud workload tags (Tenable Cloud Vulnerability Management)

Tenable Cloud Vulnerability Management (agentless scanning of AWS/Azure/GCP
workloads within Tenable One) writes into the same Tenable Vulnerability
Management backend as everything else, so it's picked up automatically in
`tenable_io` mode — no separate config needed.

For findings on cloud-discovered assets, the check additionally pulls cloud
context off Tenable's [Common Asset Attributes](https://developer.tenable.com/docs/common-asset-attributes)
and adds them as `vulnerabilities[].properties` tags on the CycloneDX payload
(shown as tags on the finding in Datadog):

| Tag | Source field(s) |
|---|---|
| `cloud-provider` | Inferred from whichever of `aws_ec2_instance_id` / `azure_vm_id` / `gcp_instance_id` is present |
| `aws-region` | `aws_region` |
| `aws-account-id` | `aws_owner_id` |
| `aws-instance-id` | `aws_ec2_instance_id` |
| `aws-ami-id` | `aws_ec2_instance_ami_id` |
| `aws-vpc-id` | `aws_vpc_id` |
| `aws-subnet-id` | `aws_subnet_id` |
| `aws-availability-zone` | `aws_availability_zone` |
| `azure-subscription-id` | `azure_subscription_id` |
| `azure-resource-group` | `azure_resource_group` |
| `azure-vm-id` | `azure_vm_id` |
| `azure-region` | `azure_location` |
| `gcp-project-id` | `gcp_project_id` |
| `gcp-zone` | `gcp_zone` |
| `gcp-instance-id` | `gcp_instance_id` |

Only fields actually present on the asset are emitted, so plain on-prem hosts
(and all Tenable.sc findings, which don't carry these attributes) get none of
these tags — just the existing `tenable:plugin_id` / `tenable:plugin_family`
properties.

## Deploying on Kubernetes (Datadog node Agent / Cluster Agent)

Do **not** just drop this check into every node Agent's `conf.d` the normal
way (e.g. via `datadog.confd` alone) — it would run once per node, hitting
Tenable's export API and re-submitting duplicate CycloneDX payloads to
Datadog on every node, every collection interval. Instead, deploy it as a
**Cluster Check**: the Cluster Agent loads the config once and dispatches it
to exactly one runner, cluster-wide, regardless of node count.

Files for this are under `k8s/`:

```
k8s/Dockerfile.cluster-check-runner        # image with pyTenable baked in
k8s/values-tenable-cluster-check.yaml      # Helm values overlay
k8s/create-secret.sh                       # creates the credentials Secret
```

### 1. Build a runner image with pyTenable

The per-node DaemonSet agents don't need pyTenable — only whichever pod
actually executes the check does. Build a small custom image just for the
Cluster Check Runner:

```bash
cd k8s
docker build -t <YOUR_REGISTRY>/datadog-agent-tenable:7-tenable \
  -f Dockerfile.cluster-check-runner .
docker push <YOUR_REGISTRY>/datadog-agent-tenable:7-tenable
```

### 2. Create the credentials Secret

```bash
TENABLE_ACCESS_KEY=... TENABLE_SECRET_KEY=... \
DD_API_KEY=... DD_APP_KEY=... \
./create-secret.sh datadog   # namespace
```

### 3. Deploy/upgrade with Helm

```bash
helm upgrade -i datadog datadog/datadog \
  -f values-datadog.yaml \
  -f k8s/values-tenable-cluster-check.yaml \
  --set-file datadog.checksd.tenable_vulns\.py=checks.d/tenable_vulns.py \
  --set clusterChecksRunner.image.repository=<YOUR_REGISTRY>/datadog-agent-tenable \
  --set clusterChecksRunner.image.tag=7-tenable \
  -n datadog
```

`--set-file` injects the actual check code from `checks.d/tenable_vulns.py`
so you don't have to hand-paste it into a values file.

### How this maps to Datadog's cluster-check machinery

| Piece | Where it lives | Why |
|---|---|---|
| Check code (`tenable_vulns.py`) | `datadog.checksd` → mounted into `/checks.d` on both node Agents and Cluster Check Runner pods | Datadog requires the check code to be present wherever it might be dispatched |
| pyTenable dependency | Baked into the Cluster Check Runner's image only | Keeps the per-node DaemonSet image lean; the check never runs on node Agents |
| Instance config (`tenable_vulns.yaml`, with `cluster_check: true`) | `clusterAgent.confd` | Marks it as a cluster check; the Cluster Agent owns dispatch |
| Credentials | Kubernetes Secret → `envFrom` on the Cluster Agent, referenced via `%%env_...%%` in the confd | Keeps API keys out of the Helm values/ConfigMap |
| Execution | `clusterChecksRunner` Deployment (2+ replicas for failover) | Cluster Agent dispatches the check to exactly one replica — extra replicas are for failover, not parallel execution |

### Verify after deploying

```bash
# Confirm the Cluster Agent sees and dispatches the check:
kubectl exec -n datadog deploy/datadog-cluster-agent -- \
  datadog-cluster-agent status | grep -A5 "tenable_vulns"

# Confirm a runner actually executed it:
kubectl exec -n datadog deploy/datadog-clusterchecks -- \
  agent status | grep -A10 "tenable_vulns"
```

⚠️ One thing to confirm on your specific Agent version: `%%env_...%%`
placeholders in a static `clusterAgent.confd` entry are normally resolved by
the Cluster Agent process itself before dispatch, which is why the Secret's
`envFrom` above is attached to the Cluster Agent rather than the runner. If
`datadog-cluster-agent status` shows the check dispatched but the runner logs
show empty/unresolved credentials, move the `envFrom` block to
`clusterChecksRunner:` instead and re-deploy — this is the one part of the
setup worth validating against a real cluster rather than trusting blindly.

## Files

```
checks.d/tenable_vulns.py          # the check itself
conf.d/tenable_vulns.d/conf.yaml   # instance configuration
```

## Install

1. Copy the check and config into your Agent's config directory:

   ```bash
   sudo cp checks.d/tenable_vulns.py /etc/datadog-agent/checks.d/tenable_vulns.py
   sudo mkdir -p /etc/datadog-agent/conf.d/tenable_vulns.d
   sudo cp conf.d/tenable_vulns.d/conf.yaml /etc/datadog-agent/conf.d/tenable_vulns.d/conf.yaml
   ```

2. Install pyTenable into the Agent's embedded Python environment:

   ```bash
   sudo /opt/datadog-agent/embedded/bin/pip install pytenable
   ```

   (On Windows: `"C:\Program Files\Datadog\Datadog Agent\embedded3\python.exe" -m pip install pytenable`)

3. Edit `conf.yaml` and fill in:
   - `tenable_access_key` / `tenable_secret_key` — [generate in Tenable.io](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm)
   - `dd_api_key` / `dd_app_key` — the application key **must** have the
     `security_monitoring_findings_write` permission
   - `dd_site` — e.g. `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`

4. Restart the Agent, then verify:

   ```bash
   sudo datadog-agent check tenable_vulns
   ```

## Cadence

Datadog automatically closes an imported vulnerability if it isn't
re-submitted within **5 hours**, so this check must run at least every
4 hours. `conf.yaml` sets `min_collection_interval: 14400` (4 hours) for
this reason — don't lower it below that without also increasing how often
you push, or previously-imported (still-open) vulnerabilities will
disappear from Datadog between runs.

## How data maps from Tenable → Datadog's CycloneDX payload

| Datadog field | Source |
|---|---|
| `metadata.component.name` / `components[].name` | The scanned asset's hostname (`asset.fqdn`/`hostname`), or a recognized OS name if `asset.operating_system` maps to Datadog's OS enum (redhat, ubuntu, windows, macos, etc.) |
| `metadata.tools.components[].name` | `scanner_name` config value (default `tenable.io`) |
| `vulnerabilities[].id` | The finding's CVE if present, otherwise `PLUGIN-<tenable_plugin_id>` |
| `vulnerabilities[].ratings[].score` / `.severity` | `plugin.cvss3_base_score` (falls back to `cvss_base_score`) and Tenable's `severity_id` mapped to Datadog's `critical/high/medium/low/info` scale |
| `vulnerabilities[].ratings[].vector` | `plugin.cvss3_vector` / `cvss_vector` |
| `vulnerabilities[].description` / `.detail` | `plugin.synopsis` / `plugin.description` |
| `vulnerabilities[].recommendation` | `plugin.solution` |
| `vulnerabilities[].cwes` | `plugin.cwe` |
| `vulnerabilities[].analysis.firstIssued` | `finding.first_found` |
| `vulnerabilities[].affects[].ref` | The asset's `bom-ref`, since Tenable's standard host-based scan doesn't provide per-package purls the way an SBOM scanner does — the whole host is treated as the "affected component" |
| `vulnerabilities[].properties` | `tenable:plugin_id`, `tenable:plugin_family` tags |

Only findings with `state` in `open`/`reopened` and `severity` in the
configured `min_severities` list are exported and imported, since the
Datadog endpoint's built-in auto-close behavior already handles
resolved/fixed vulnerabilities dropping out on their own once they stop
being re-submitted.

## Differential exports

The check saves a high-water mark (`last_indexed_at`) via the Agent's
persistent cache after each run and uses it as the `last_found` filter on
the next run, so only newly found/updated Tenable findings are re-sent each
cycle — matching Tenable's [recommended differential export pattern](https://developer.tenable.com/docs/retrieve-vulnerability-data-from-tenableio).
On the very first run (no cache yet), it falls back to `lookback_hours`
(default 6h).

## Payload size

Each CycloneDX request is capped at Datadog's 1 MiB limit. The check
batches at most 150 vulnerabilities per request per asset and will further
split a batch in half if the serialized JSON still exceeds ~900 KB.
