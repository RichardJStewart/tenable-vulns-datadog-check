# tenable_vulns.py
#
# Custom Datadog Agent check.
#
# Pulls vulnerability findings from either:
#   - Tenable Vulnerability Management (Tenable.io), via the vulnerability
#     export API (tio.exports.vulns()), or
#   - Tenable Security Center (on-prem), via the analysis API
#     (sc.analysis.vulns()),
# using pyTenable, converts them to CycloneDX 1.5 BOMs (one per affected
# asset), and imports them into Datadog Cloud Security via:
#
#     POST /api/v2/security/vulnerabilities
#
# See: "Import vulnerabilities into Datadog Cloud Security",
#      https://developer.tenable.com/docs/introduction-to-pytenable, and
#      https://developer.tenable.com/reference/navigate
#
# Set `tenable_platform: tenable_io` (default) or `tenable_platform: tenable_sc`
# in conf.yaml to choose the data source. Everything downstream (CycloneDX
# construction, batching, submission to Datadog) is shared between both.
#
# Install location (Agent < 7.x "custom check" layout):
#   /etc/datadog-agent/checks.d/tenable_vulns.py
#   /etc/datadog-agent/conf.d/tenable_vulns.d/conf.yaml
#
# Requires the pyTenable package to be installed into the Agent's embedded
# Python environment, e.g.:
#   /opt/datadog-agent/embedded/bin/pip install pytenable

from __future__ import annotations

import time
import datetime as dt
import json
from collections import defaultdict

import requests

from datadog_checks.base import AgentCheck
from datadog_checks.base.errors import CheckException

try:
    from tenable.io import TenableIO
except ImportError:
    TenableIO = None

try:
    from tenable.sc import TenableSC
except ImportError:
    TenableSC = None

__version__ = "1.1.0"

# Datadog vulnerabilities are auto-closed by the backend after 5 hours if not
# re-submitted, so this check should run at least every 4 hours. This is only
# a soft-enforced default; the real cadence is set via min_collection_interval
# in conf.yaml.
DEFAULT_LOOKBACK_HOURS = 6

# Stay comfortably under Datadog's 1 MiB payload limit per request.
MAX_VULNS_PER_PAYLOAD = 150
MAX_PAYLOAD_BYTES = 900 * 1024  # leave headroom under the 1 MiB (1,048,576 byte) cap

# Tenable severity_id -> CycloneDX/Datadog severity string
SEVERITY_MAP = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
}

# Datadog's allowed operating-system component names
# (components.name enum from the Datadog vulnerabilities import spec)
DD_OS_NAMES = {
    "alma", "alpine", "amazon", "azurelinux", "bottlerocket", "cbl-mariner",
    "chainguard", "centos", "debian", "fedora", "opensuse", "opensuse-leap",
    "opensuse-tumbleweed", "oracle", "photon", "redhat", "rocky", "slem",
    "sles", "ubuntu", "wolfi", "windows", "macos",
}

# Best-effort mapping from common Tenable/OS free-text families to Datadog's enum
OS_FAMILY_ALIASES = {
    "red hat": "redhat",
    "rhel": "redhat",
    "amazon linux": "amazon",
    "amzn": "amazon",
    "suse linux enterprise": "sles",
    "sles": "sles",
    "opensuse leap": "opensuse-leap",
    "opensuse tumbleweed": "opensuse-tumbleweed",
    "os x": "macos",
    "macos": "macos",
    "microsoft windows": "windows",
    "windows": "windows",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "fedora": "fedora",
    "oracle linux": "oracle",
    "rocky linux": "rocky",
    "alma linux": "alma",
    "alpine": "alpine",
}


def _guess_dd_os_name(raw_name):
    """Map a free-text OS name from Tenable to Datadog's fixed OS name enum."""
    if not raw_name:
        return None
    lowered = raw_name.strip().lower()
    if lowered in DD_OS_NAMES:
        return lowered
    for alias, dd_name in OS_FAMILY_ALIASES.items():
        if alias in lowered:
            return dd_name
    return None


# Common Asset Attribute fields (Tenable.io) that identify cloud workloads,
# mapped to the tag name we emit as a CycloneDX vulnerability property.
# https://developer.tenable.com/docs/common-asset-attributes
CLOUD_ASSET_TAG_FIELDS = {
    "aws_region": "aws-region",
    "aws_owner_id": "aws-account-id",
    "aws_ec2_instance_id": "aws-instance-id",
    "aws_ec2_instance_ami_id": "aws-ami-id",
    "aws_vpc_id": "aws-vpc-id",
    "aws_subnet_id": "aws-subnet-id",
    "aws_availability_zone": "aws-availability-zone",
    "azure_subscription_id": "azure-subscription-id",
    "azure_resource_group": "azure-resource-group",
    "azure_vm_id": "azure-vm-id",
    "azure_location": "azure-region",
    "gcp_project_id": "gcp-project-id",
    "gcp_zone": "gcp-zone",
    "gcp_instance_id": "gcp-instance-id",
}

# Presence of any of these fields identifies which cloud provider an asset
# belongs to, so we can also emit a single "cloud-provider" tag.
CLOUD_PROVIDER_MARKER_FIELDS = {
    "aws_ec2_instance_id": "aws",
    "azure_vm_id": "azure",
    "gcp_instance_id": "gcp",
}


class TenableVulnsCheck(AgentCheck):
    __NAMESPACE__ = "tenable_vulns"

    def __init__(self, name, init_config, instances):
        super(TenableVulnsCheck, self).__init__(name, init_config, instances)
        self._last_indexed_at_key = "last_indexed_at"

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _platform(self):
        platform = self.instance.get("tenable_platform", "tenable_io")
        if platform not in ("tenable_io", "tenable_sc"):
            raise CheckException(
                "tenable_platform must be 'tenable_io' or 'tenable_sc', got: {}".format(platform)
            )
        return platform

    def _get_tenable_client(self):
        if self._platform() == "tenable_sc":
            return self._get_tenable_sc_client()
        return self._get_tenable_io_client()

    def _get_tenable_io_client(self):
        access_key = self.instance.get("tenable_access_key")
        secret_key = self.instance.get("tenable_secret_key")
        if not access_key or not secret_key:
            raise CheckException(
                "tenable_access_key and tenable_secret_key are required in conf.yaml "
                "when tenable_platform is 'tenable_io'"
            )
        if TenableIO is None:
            raise CheckException(
                "pyTenable is not installed. Run: "
                "/opt/datadog-agent/embedded/bin/pip install pytenable"
            )
        return TenableIO(
            access_key=access_key,
            secret_key=secret_key,
            vendor="Datadog",
            product="tenable_vulns custom check",
            build=__version__,
        )

    def _get_tenable_sc_client(self):
        if TenableSC is None:
            raise CheckException(
                "pyTenable is not installed. Run: "
                "/opt/datadog-agent/embedded/bin/pip install pytenable"
            )

        host = self.instance.get("sc_host")
        if not host:
            raise CheckException("sc_host is required in conf.yaml when tenable_platform is 'tenable_sc'")

        port = int(self.instance.get("sc_port", 443))
        ssl_verify = bool(self.instance.get("sc_ssl_verify", True))

        access_key = self.instance.get("sc_access_key")
        secret_key = self.instance.get("sc_secret_key")
        username = self.instance.get("sc_username")
        password = self.instance.get("sc_password")

        if access_key and secret_key:
            # Modern versions of pyTenable accept API keys directly in the constructor.
            sc = TenableSC(
                host,
                port=port,
                access_key=access_key,
                secret_key=secret_key,
                ssl_verify=ssl_verify,
                vendor="Datadog",
                product="tenable_vulns custom check",
                build=__version__,
            )
        elif username and password:
            sc = TenableSC(host, port=port, ssl_verify=ssl_verify)
            sc.login(username=username, password=password)
        else:
            raise CheckException(
                "Provide either sc_access_key/sc_secret_key or sc_username/sc_password in conf.yaml"
            )
        return sc

    def _dd_site_url(self):
        site = self.instance.get("dd_site", "datadoghq.com")
        return "https://api.{}".format(site)

    def _dd_headers(self):
        api_key = self.instance.get("dd_api_key")
        app_key = self.instance.get("dd_app_key")
        if not api_key or not app_key:
            raise CheckException("dd_api_key and dd_app_key are required in conf.yaml")
        return {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        }

    def _lookback_start(self):
        """
        Determine the start of the export window. Uses the persistent cache
        to pick up where the last run left off (differential export), falling
        back to a configurable lookback window on first run.
        """
        cached = self.read_persistent_cache(self._last_indexed_at_key)
        if cached:
            try:
                return int(cached)
            except (TypeError, ValueError):
                pass
        lookback_hours = int(self.instance.get("lookback_hours", DEFAULT_LOOKBACK_HOURS))
        return int(time.time()) - lookback_hours * 3600

    # ------------------------------------------------------------------
    # Tenable export
    # ------------------------------------------------------------------

    def _export_tenable_vulns(self, client, since_epoch):
        """
        Yields findings in a single normalized ("Tenable.io export shape") form
        regardless of whether the source is Tenable.io or Tenable Security Center.
        """
        if self._platform() == "tenable_sc":
            for record in self._export_sc_vulns(client, since_epoch):
                yield self._normalize_sc_finding(record)
        else:
            severities = self.instance.get("min_severities", ["low", "medium", "high", "critical"])
            kwargs = {
                "state": ["open", "reopened"],
                "severity": severities,
                "last_found": since_epoch,
            }
            if self.instance.get("include_unlicensed", False):
                kwargs["include_unlicensed"] = True

            self.log.debug("Requesting Tenable.io vulnerability export with filters: %s", kwargs)
            for finding in client.exports.vulns(**kwargs):
                yield finding

    _SC_SEVERITY_NAME_TO_ID = {"low": "1", "medium": "2", "high": "3", "critical": "4"}

    def _export_sc_vulns(self, sc, since_epoch):
        """
        Queries Tenable Security Center's analysis API for active (unmitigated)
        vulnerability instances last seen since `since_epoch`. Uses the default
        'vulndetails' tool with sourceType='cumulative', which returns only
        currently-active findings (mitigated/patched vulns are excluded
        automatically, so no explicit state filter is needed).
        """
        severity_names = self.instance.get("min_severities", ["low", "medium", "high", "critical"])
        severity_ids = ",".join(
            self._SC_SEVERITY_NAME_TO_ID[s] for s in severity_names if s in self._SC_SEVERITY_NAME_TO_ID
        )
        now_epoch = int(time.time())

        filters = [("severity", "=", severity_ids)]
        # NOTE: verify this date-range filter syntax against your SC version --
        # Tenable Security Center's analysis filters have varied across
        # releases. This "<start>:<end>" epoch-range form is the commonly
        # documented pattern for lastSeen; test it with `datadog-agent check
        # tenable_vulns` before relying on it in production.
        filters.append(("lastSeen", "=", "{}:{}".format(since_epoch, now_epoch)))

        self.log.debug("Requesting Tenable.sc analysis with filters: %s", filters)
        for record in sc.analysis.vulns(*filters, tool="vulndetails", sourceType="cumulative"):
            yield record

    @staticmethod
    def _epoch_to_iso(value):
        try:
            return dt.datetime.utcfromtimestamp(int(value)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            return None

    def _normalize_sc_finding(self, record):
        """
        Converts a Tenable Security Center analysis record (from sc.analysis.vulns())
        into the same shape used by Tenable.io's export API, so downstream
        CycloneDX-building code doesn't need to know which platform it came from.
        """
        severity = record.get("severity") or {}
        try:
            severity_id = int(severity.get("id"))
        except (TypeError, ValueError):
            severity_id = None

        cve_raw = record.get("cve") or ""
        cves = [c.strip() for c in cve_raw.split(",") if c.strip()]

        family = record.get("family") or {}
        repository = record.get("repository") or {}

        # SC has no Tenable.io-style asset UUID; build a stable-enough key
        # from IP + repository so findings on the same host group together.
        ip = record.get("ip") or record.get("dnsName") or "unknown-host"
        repo_id = repository.get("id", "")
        asset_uuid = "{}-{}".format(ip, repo_id)

        os_raw = record.get("operatingSystem")
        operating_system = [os_raw] if os_raw else []

        cwes = []
        xref = record.get("xref") or ""
        for entry in xref.split(","):
            entry = entry.strip()
            if entry.upper().startswith("CWE:"):
                try:
                    cwes.append(str(int(entry.split(":", 1)[1])))
                except ValueError:
                    continue

        return {
            "asset": {
                "uuid": asset_uuid,
                "fqdn": record.get("dnsName") or None,
                "hostname": record.get("dnsName") or record.get("netbiosName") or ip,
                "ipv4": [ip] if ip else [],
                "operating_system": operating_system,
            },
            "plugin": {
                "id": record.get("pluginID"),
                "name": record.get("pluginName"),
                "family": {"name": family.get("name", "")},
                "cve": cves,
                "cvss3_base_score": record.get("cvssV3BaseScore") or None,
                "cvss3_vector": record.get("cvssV3Vector") or None,
                "cvss_base_score": record.get("baseScore") or record.get("cvssBaseScore") or None,
                "cvss_vector": record.get("cvssVector") or None,
                "synopsis": record.get("synopsis"),
                "description": record.get("description"),
                "solution": record.get("solution"),
                "cwe": cwes,
            },
            "severity_id": severity_id,
            "first_found": self._epoch_to_iso(record.get("firstSeen")),
        }

    # ------------------------------------------------------------------
    # CycloneDX construction
    # ------------------------------------------------------------------

    def _asset_component(self, asset):
        """Build the CycloneDX component representing the scanned asset (host)."""
        asset_uuid = asset.get("uuid") or asset.get("id") or "unknown-asset"
        hostname = (
            asset.get("fqdn")
            or asset.get("hostname")
            or asset.get("netbios_name")
            or (asset.get("ipv4") or [None])[0]
            or asset_uuid
        )
        os_names = asset.get("operating_system") or []
        dd_os_name = None
        for raw in os_names:
            dd_os_name = _guess_dd_os_name(raw)
            if dd_os_name:
                break

        bom_ref = "{}-asset".format(asset_uuid)
        component = {
            "bom-ref": bom_ref,
            "type": "operating-system" if dd_os_name else "application",
            "name": dd_os_name if dd_os_name else hostname,
        }
        if dd_os_name and os_names:
            # try to pull a version string out of the raw OS banner, best effort
            component["version"] = os_names[0]

        return bom_ref, hostname, component

    @staticmethod
    def _cloud_properties(asset):
        """
        Pulls cloud-workload context (AWS/Azure/GCP account, region, instance
        ID, etc.) off a Tenable.io asset object and returns it as CycloneDX
        vulnerability properties, matching Datadog's tag format ("name:value").
        Only present on assets discovered via Tenable Cloud Vulnerability
        Management / cloud connectors -- returns [] for plain on-prem hosts
        and for Tenable.sc (whose normalized asset dict won't have these
        fields at all).
        """
        props = []
        provider = None
        for field, provider_name in CLOUD_PROVIDER_MARKER_FIELDS.items():
            if asset.get(field):
                provider = provider_name
                break
        if provider:
            props.append({"name": "cloud-provider", "value": provider})

        for field, tag_name in CLOUD_ASSET_TAG_FIELDS.items():
            value = asset.get(field)
            if value:
                props.append({"name": tag_name, "value": str(value)})

        return props

    def _build_vulnerability_entry(self, finding):
        plugin = finding.get("plugin", {}) or {}
        asset = finding.get("asset", {}) or {}
        cves = plugin.get("cve") or []
        vuln_id = cves[0] if cves else "PLUGIN-{}".format(plugin.get("id", "unknown"))

        severity_id = finding.get("severity_id")
        severity = SEVERITY_MAP.get(severity_id, "unknown")
        score = plugin.get("cvss3_base_score") or plugin.get("cvss_base_score") or 0
        vector = plugin.get("cvss3_vector") or plugin.get("cvss_vector")

        rating = {"score": float(score) if score else 0, "severity": severity}
        if vector:
            rating["vector"] = vector

        entry = {
            "id": vuln_id,
            "ratings": [rating],
            "properties": [
                {"name": "tenable:plugin_id", "value": str(plugin.get("id", ""))},
                {"name": "tenable:plugin_family", "value": str(plugin.get("family", {}).get("name", ""))},
            ] + self._cloud_properties(asset),
        }

        synopsis = plugin.get("synopsis")
        description = plugin.get("description")
        if synopsis:
            entry["description"] = synopsis
        if description:
            entry["detail"] = description

        solution = plugin.get("solution")
        if solution:
            entry["recommendation"] = solution

        first_found = finding.get("first_found")
        if first_found:
            entry["analysis"] = {"firstIssued": first_found}

        cwes = plugin.get("cwe")
        if cwes:
            cleaned = []
            for c in cwes:
                try:
                    cleaned.append(int(str(c).upper().replace("CWE-", "")))
                except ValueError:
                    continue
            if cleaned:
                entry["cwes"] = cleaned

        return entry

    def _build_boms_for_assets(self, findings_by_asset, scanner_name):
        """
        Yields (asset_hostname, bom_dict) tuples, one per asset, splitting a
        single asset's findings across multiple BOMs if needed to respect
        MAX_VULNS_PER_PAYLOAD / MAX_PAYLOAD_BYTES.
        """
        for asset_key, data in findings_by_asset.items():
            bom_ref = data["bom_ref"]
            hostname = data["hostname"]
            component = data["component"]
            vulnerabilities = data["vulnerabilities"]

            for i in range(0, len(vulnerabilities), MAX_VULNS_PER_PAYLOAD):
                chunk = vulnerabilities[i:i + MAX_VULNS_PER_PAYLOAD]
                bom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "metadata": {
                        "component": {
                            "bom-ref": bom_ref,
                            "type": component["type"],
                            "name": component["name"],
                        },
                        "tools": {"components": [{"type": "application", "name": scanner_name}]},
                    },
                    "components": [component],
                    "vulnerabilities": chunk,
                }
                payload_bytes = len(json.dumps(bom).encode("utf-8"))
                if payload_bytes > MAX_PAYLOAD_BYTES:
                    # Split further in half if still too large.
                    half = max(1, len(chunk) // 2)
                    for sub in (chunk[:half], chunk[half:]):
                        if not sub:
                            continue
                        sub_bom = dict(bom)
                        sub_bom["vulnerabilities"] = sub
                        yield hostname, sub_bom
                else:
                    yield hostname, bom

    # ------------------------------------------------------------------
    # Datadog submission
    # ------------------------------------------------------------------

    def _submit_bom(self, bom, hostname):
        url = "{}/api/v2/security/vulnerabilities".format(self._dd_site_url())
        resp = requests.post(url, headers=self._dd_headers(), data=json.dumps(bom), timeout=30)
        n_vulns = len(bom.get("vulnerabilities", []))
        if resp.status_code == 200:
            self.log.debug("Imported %d vuln(s) for asset %s", n_vulns, hostname)
            self.count("vulnerabilities.imported", n_vulns, tags=["asset:{}".format(hostname)])
        else:
            self.log.error(
                "Failed to import %d vuln(s) for asset %s: HTTP %s - %s",
                n_vulns, hostname, resp.status_code, resp.text[:500],
            )
            self.count("vulnerabilities.import_errors", n_vulns, tags=["asset:{}".format(hostname)])
        return resp.status_code == 200

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def check(self, instance):
        run_started = int(time.time())
        scanner_name = self.instance.get("scanner_name", "tenable.io")

        try:
            tenable_client = self._get_tenable_client()
        except CheckException as e:
            self.service_check("connectivity", AgentCheck.CRITICAL, message=str(e))
            raise

        since_epoch = self._lookback_start()
        self.log.info("Exporting Tenable vulnerabilities found since %s", since_epoch)

        findings_by_asset = defaultdict(lambda: {
            "bom_ref": None, "hostname": None, "component": None, "vulnerabilities": []
        })

        n_findings = 0
        try:
            for finding in self._export_tenable_vulns(tenable_client, since_epoch):
                asset = finding.get("asset", {}) or {}
                asset_key = asset.get("uuid") or asset.get("id")
                if not asset_key:
                    continue

                if findings_by_asset[asset_key]["component"] is None:
                    bom_ref, hostname, component = self._asset_component(asset)
                    findings_by_asset[asset_key]["bom_ref"] = bom_ref
                    findings_by_asset[asset_key]["hostname"] = hostname
                    findings_by_asset[asset_key]["component"] = component

                vuln_entry = self._build_vulnerability_entry(finding)
                vuln_entry["affects"] = [{"ref": findings_by_asset[asset_key]["bom_ref"]}]
                findings_by_asset[asset_key]["vulnerabilities"].append(vuln_entry)
                n_findings += 1
        except Exception as e:
            self.service_check("connectivity", AgentCheck.CRITICAL, message=str(e))
            raise CheckException("Error exporting vulnerabilities from {}: {}".format(self._platform(), e))

        self.service_check("connectivity", AgentCheck.OK)
        self.gauge("tenable.findings_exported", n_findings)

        if n_findings == 0:
            self.log.info("No new/open Tenable vulnerabilities found in the export window.")
            self._save_watermark(run_started)
            return

        n_ok = 0
        n_total = 0
        for hostname, bom in self._build_boms_for_assets(findings_by_asset, scanner_name):
            n_total += 1
            if self._submit_bom(bom, hostname):
                n_ok += 1

        self.gauge("tenable.assets_processed", len(findings_by_asset))
        self.log.info(
            "Submitted %d/%d CycloneDX payload(s) to Datadog for %d asset(s), %d finding(s) total.",
            n_ok, n_total, len(findings_by_asset), n_findings,
        )

        self._save_watermark(run_started)

    def _save_watermark(self, run_started):
        # Small overlap to avoid missing findings indexed right at the boundary.
        self.write_persistent_cache(self._last_indexed_at_key, str(run_started - 300))
