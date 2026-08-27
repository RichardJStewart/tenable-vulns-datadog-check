# Tenable → Datadog Cloud Security vulnerability import (custom Agent check)

This is a custom Datadog Agent check that:

1. Pulls open vulnerability findings from **Tenable Vulnerability Management
   (Tenable.io)** using [pyTenable](https://developer.tenable.com/docs/introduction-to-pytenable)'s
   vulnerability export API (`tio.exports.vulns()`, a wrapper around
   [`/vulns/export`](https://developer.tenable.com/reference/navigate)).
2. Groups findings by asset and converts them into **CycloneDX 1.5** BOMs.
3. Submits each BOM to Datadog's vulnerability import endpoint:
   `POST /api/v2/security/vulnerabilities`.

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

