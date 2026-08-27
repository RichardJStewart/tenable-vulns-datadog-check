# tenable_vulns.py
#
# Custom Datadog Agent check.
#
# Pulls vulnerability findings from Tenable Vulnerability Management (Tenable.io)
# using pyTenable, converts them to CycloneDX 1.5 BOMs (one per affected asset),
# and imports them into Datadog Cloud Security via:
#
#     POST /api/v2/security/vulnerabilities
#
# See: "Import vulnerabilities into Datadog Cloud Security" and
#      https://developer.tenable.com/docs/introduction-to-pytenable
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

__version__ = "1.0.0"

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


class TenableVulnsCheck(AgentCheck):
    __NAMESPACE__ = "tenable_vulns"

    def __init__(self, name, init_config, instances):
        super(TenableVulnsCheck, self).__init__(name, init_config, instances)
        self._last_indexed_at_key = "last_indexed_at"

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _get_tenable_client(self):
        access_key = self.instance.get("tenable_access_key")
        secret_key = self.instance.get("tenable_secret_key")
        if not access_key or not secret_key:
            raise CheckException(
                "tenable_access_key and tenable_secret_key are required in conf.yaml"
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

    def _export_tenable_vulns(self, tio, since_epoch):
        """
        Streams vulnerability findings from Tenable.io using the vulnerability
        export API (wrapped by pyTenable's tio.exports.vulns()), filtered to
        open/reopened findings last seen since `since_epoch`.
        """
        severities = self.instance.get("min_severities", ["low", "medium", "high", "critical"])
        kwargs = {
            "state": ["open", "reopened"],
            "severity": severities,
            "last_found": since_epoch,
        }
        if self.instance.get("include_unlicensed", False):
            kwargs["include_unlicensed"] = True

        self.log.debug("Requesting Tenable vulnerability export with filters: %s", kwargs)
        for finding in tio.exports.vulns(**kwargs):
            yield finding

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

    def _build_vulnerability_entry(self, finding):
        plugin = finding.get("plugin", {}) or {}
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
            ],
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
            tio = self._get_tenable_client()
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
            for finding in self._export_tenable_vulns(tio, since_epoch):
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
            raise CheckException("Error exporting vulnerabilities from Tenable.io: {}".format(e))

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
