#!/usr/bin/env python3
"""Daily vulnerability intelligence and local exposure scanner."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import email.utils
import hashlib
import json
import os
import re
import sys
import time
import textwrap
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
X_RECENT_SEARCH_URL = "https://api.twitter.com/2/tweets/search/recent"
DEFAULT_TIMEOUT_SECONDS = 25
SOURCE_FAILURES: set[str] = set()
REVIEW_SUPPRESSING_STATUSES = {"not_affected", "false_positive", "risk_accepted"}
REVIEW_STATUSES = sorted(REVIEW_SUPPRESSING_STATUSES | {"affected"})


ECOSYSTEM_ALIASES = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
}


@dataclasses.dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    project: str
    manifest: str
    source: str

    @property
    def key(self) -> tuple[str, str, str | None, str, str]:
        return (
            self.ecosystem.lower(),
            self.name.lower(),
            self.version,
            self.project,
            self.manifest,
        )


@dataclasses.dataclass(frozen=True)
class ThreatItem:
    source: str
    title: str
    url: str | None
    published: str | None
    cves: tuple[str, ...]
    text: str
    severity: float | None = None


@dataclasses.dataclass(frozen=True)
class Exposure:
    kind: str
    severity: str
    source: str
    project: str | None
    dependency: Dependency | None
    title: str
    advisory_id: str | None
    url: str | None
    evidence: str


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return json.load(handle)


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_date(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()


def request_json(url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> Any:
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {"User-Agent": "codex-guardtower/0.1"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def request_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "codex-guardtower/0.1"})
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


def record_source_failure(source: str, message: str) -> None:
    SOURCE_FAILURES.add(source)
    print(message, file=sys.stderr)


def request_json_auth(url: str, token: str) -> Any:
    return request_json(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "codex-guardtower/0.1",
        },
    )


def project_name_for(path: Path) -> str:
    if path.name in {"package.json", "pyproject.toml", "go.mod", "Cargo.lock", "Gemfile.lock"}:
        return path.parent.name
    return path.parent.name


def clean_package_name(raw: str) -> str | None:
    value = raw.strip().strip("\"'`")
    value = re.sub(r"\[.*\]$", "", value)
    value = re.split(r"\s*(?:==|>=|<=|~=|!=|>|<|=)\s*", value, maxsplit=1)[0]
    value = value.strip()
    if not value or value.startswith(("#", "--", "-r ", "git+", "http://", "https://")):
        return None
    return value


def clean_version(raw: str | None) -> str | None:
    if not raw:
        return None
    value = raw.strip().strip("\"'`")
    if not value or value == "*":
        return None
    match = re.search(r"(?<![<>=!~])(?:==|=)\s*([A-Za-z0-9_.!+\-]+)", value)
    if match:
        return match.group(1)
    if re.fullmatch(r"[0-9][A-Za-z0-9_.!+\-]*", value):
        return value
    return None


def add_dependency(
    deps: dict[tuple[str, str, str | None, str, str], Dependency],
    ecosystem: str,
    name: str | None,
    version: str | None,
    project: str,
    manifest: Path,
    source: str,
) -> None:
    if not name:
        return
    normalized = ECOSYSTEM_ALIASES.get(ecosystem.lower(), ecosystem)
    dep = Dependency(
        ecosystem=normalized,
        name=name,
        version=clean_version(version),
        project=project,
        manifest=str(manifest),
        source=source,
    )
    deps.setdefault(dep.key, dep)


def parse_package_json(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    payload = json.loads(path.read_text())
    project = payload.get("name") or path.parent.name
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = payload.get(section)
        if isinstance(values, dict):
            for name, version in values.items():
                add_dependency(deps, "npm", name, str(version), project, path, section)


def parse_package_lock(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    payload = json.loads(path.read_text())
    project = path.parent.name
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not package_path or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            if not name and "node_modules/" in package_path:
                name = package_path.rsplit("node_modules/", 1)[1]
            add_dependency(deps, "npm", name, meta.get("version"), project, path, "package-lock")
    values = payload.get("dependencies")
    if isinstance(values, dict):
        for name, meta in values.items():
            version = meta.get("version") if isinstance(meta, dict) else None
            add_dependency(deps, "npm", name, version, project, path, "package-lock")


def parse_pyproject(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    payload = tomllib.loads(path.read_text())
    project = payload.get("project", {}).get("name") or path.parent.name
    for item in payload.get("project", {}).get("dependencies", []) or []:
        name = clean_package_name(str(item))
        add_dependency(deps, "PyPI", name, str(item), project, path, "project.dependencies")
    optional = payload.get("project", {}).get("optional-dependencies", {}) or {}
    for values in optional.values():
        for item in values or []:
            name = clean_package_name(str(item))
            add_dependency(deps, "PyPI", name, str(item), project, path, "project.optional-dependencies")
    poetry = payload.get("tool", {}).get("poetry", {})
    poetry_project = poetry.get("name") or project
    for section in ("dependencies", "dev-dependencies"):
        values = poetry.get(section)
        if isinstance(values, dict):
            for name, spec in values.items():
                if name.lower() != "python":
                    add_dependency(deps, "PyPI", name, str(spec), poetry_project, path, f"tool.poetry.{section}")
    for group_name, group in (poetry.get("group") or {}).items():
        values = group.get("dependencies") if isinstance(group, dict) else None
        if isinstance(values, dict):
            for name, spec in values.items():
                add_dependency(deps, "PyPI", name, str(spec), poetry_project, path, f"tool.poetry.group.{group_name}")


def parse_requirements(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    project = path.parent.name
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.split("#", 1)[0].strip()
        name = clean_package_name(stripped)
        if name:
            add_dependency(deps, "PyPI", name, stripped, project, path, "requirements")


def parse_poetry_lock(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    payload = tomllib.loads(path.read_text())
    project = path.parent.name
    for package in payload.get("package", []) or []:
        if isinstance(package, dict):
            add_dependency(deps, "PyPI", package.get("name"), package.get("version"), project, path, "poetry.lock")


def parse_pipfile_lock(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    payload = json.loads(path.read_text())
    project = path.parent.name
    for section in ("default", "develop"):
        values = payload.get(section)
        if isinstance(values, dict):
            for name, meta in values.items():
                version = meta.get("version") if isinstance(meta, dict) else None
                add_dependency(deps, "PyPI", name, version, project, path, f"Pipfile.lock.{section}")


def parse_go_mod(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    project = path.parent.name
    in_require = False
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.split("//", 1)[0].strip()
        if stripped == "require (":
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("require "):
            fields = stripped.removeprefix("require ").split()
        elif in_require:
            fields = stripped.split()
        else:
            continue
        if len(fields) >= 2:
            add_dependency(deps, "Go", fields[0], fields[1], project, path, "go.mod")


def parse_cargo_lock(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    payload = tomllib.loads(path.read_text())
    project = path.parent.name
    for package in payload.get("package", []) or []:
        if isinstance(package, dict):
            add_dependency(deps, "crates.io", package.get("name"), package.get("version"), project, path, "Cargo.lock")


def parse_gemfile_lock(path: Path, deps: dict[tuple[str, str, str | None, str, str], Dependency]) -> None:
    project = path.parent.name
    in_specs = False
    for line in path.read_text(errors="replace").splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"\s{4}([A-Za-z0-9_.\-]+) \(([^)]+)\)", line)
        if match:
            add_dependency(deps, "RubyGems", match.group(1), match.group(2), project, path, "Gemfile.lock")


PARSERS = {
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "pyproject.toml": parse_pyproject,
    "requirements.txt": parse_requirements,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
}


def discover_manifest_paths(config: dict[str, Any]) -> list[Path]:
    manifest_names = set(config.get("manifest_names") or PARSERS.keys())
    roots = discover_scan_roots(config)
    exclude_dirs = set(config.get("exclude_dirs") or [])
    exclude_hidden_dirs = bool(config.get("exclude_hidden_dirs", True))
    max_depth = int(config.get("max_depth", 5))
    paths: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        root_depth = len(root.parts)
        for current_root, dirs, files in os.walk(root):
            current = Path(current_root)
            depth = len(current.parts) - root_depth
            if depth >= max_depth:
                dirs[:] = []
            dirs[:] = [
                dirname
                for dirname in dirs
                if dirname not in exclude_dirs and not dirname.endswith(".app")
                and not (exclude_hidden_dirs and dirname.startswith(".") and dirname != ".github")
            ]
            for filename in files:
                if filename in manifest_names:
                    paths.append(current / filename)
    return sorted(set(paths))


def discover_scan_roots(config: dict[str, Any]) -> list[Path]:
    configured = [Path(raw).expanduser().resolve() for raw in config.get("scan_roots") or []]
    if not config.get("discover_git_roots", True):
        return configured
    exclude_dirs = set(config.get("exclude_dirs") or [])
    exclude_hidden_dirs = bool(config.get("exclude_hidden_dirs", True))
    search_depth = int(config.get("git_root_search_depth", 3))
    discovered: set[Path] = set()
    for root in configured:
        if not root.exists():
            continue
        if (root / ".git").exists():
            discovered.add(root)
            continue
        root_depth = len(root.parts)
        for current_root, dirs, _files in os.walk(root):
            current = Path(current_root)
            depth = len(current.parts) - root_depth
            if depth >= search_depth:
                dirs[:] = []
            dirs[:] = [
                dirname
                for dirname in dirs
                if dirname not in exclude_dirs
                and not dirname.endswith(".app")
                and not (exclude_hidden_dirs and dirname.startswith("."))
            ]
            if (current / ".git").exists():
                discovered.add(current)
                dirs[:] = []
    return sorted(discovered) or configured


def inventory_dependencies(config: dict[str, Any]) -> tuple[list[Dependency], list[str]]:
    deps: dict[tuple[str, str, str | None, str, str], Dependency] = {}
    errors: list[str] = []
    for manifest in discover_manifest_paths(config):
        parser = PARSERS.get(manifest.name)
        if parser is None:
            continue
        try:
            parser(manifest, deps)
        except Exception as exc:  # noqa: BLE001 - report parser failure without aborting the scan.
            errors.append(f"{manifest}: {exc}")
    return sorted(deps.values(), key=lambda dep: (dep.ecosystem, dep.name, dep.project)), errors


def osv_queries(dependencies: list[Dependency]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, str | None], Dependency] = {}
    for dep in dependencies:
        deduped.setdefault((dep.ecosystem, dep.name, dep.version), dep)
    queries = []
    for dep in deduped.values():
        query: dict[str, Any] = {
            "package": {
                "ecosystem": dep.ecosystem,
                "name": dep.name,
            }
        }
        if dep.version:
            query["version"] = dep.version
        queries.append(query)
    return queries


def chunked(values: list[Any], size: int) -> list[list[Any]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def fetch_osv_vulnerabilities(
    dependencies: list[Dependency],
    no_network: bool,
    *,
    query_versionless: bool,
) -> dict[tuple[str, str, str | None], list[dict[str, Any]]]:
    if no_network:
        return {}
    queries = osv_queries(dependencies)
    results: dict[tuple[str, str, str | None], list[dict[str, Any]]] = {}
    dep_keys = sorted(
        {
            (dep.ecosystem, dep.name, dep.version)
            for dep in dependencies
            if query_versionless or dep.version
        },
        key=lambda item: (item[0], item[1], item[2] or ""),
    )
    ordered_queries = []
    for ecosystem, name, version in dep_keys:
        query: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
        if version:
            query["version"] = version
        ordered_queries.append(((ecosystem, name, version), query))
    for chunk in chunked(ordered_queries, 500):
        data = json.dumps({"queries": [query for _, query in chunk]}).encode("utf-8")
        try:
            payload = request_json(OSV_QUERY_BATCH_URL, headers={"Content-Type": "application/json", "User-Agent": "codex-guardtower/0.1"}, data=data)
        except Exception as exc:  # noqa: BLE001
            record_source_failure("osv", f"warning: OSV query failed: {exc}")
            continue
        for (key, _query), result in zip(chunk, payload.get("results", []), strict=False):
            vulns = result.get("vulns") if isinstance(result, dict) else None
            if vulns:
                results[key] = vulns
        time.sleep(0.2)
    return results


def extract_cves(text: str) -> tuple[str, ...]:
    return tuple(sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)), key=str.upper))


def text_excerpt(value: str | None, limit: int = 360) -> str:
    normalized = " ".join(str(value or "").split())
    if len(normalized) <= limit:
        return normalized
    return textwrap.shorten(normalized, width=limit, placeholder="...")


def is_security_exploit_news(title: str, body: str) -> bool:
    text = f"{title}\n{body}".lower()
    roundup_patterns = (
        r"\btop\s+(?:ai|tech|cybersecurity|security)?\s*news\b",
        r"\b(?:ai|tech|security|cybersecurity)\s+news\s+today\b",
        r"\bnewsletter\b",
        r"\broundup\b",
        r"\bdaily\s+brief(?:ing)?\b",
        r"\bweekly\s+brief(?:ing)?\b",
        r"\bwhat happened today\b",
        r"\byou don.t understand what you are reading\b",
        r"\bmost of those items\b",
        r"\bif you really believe this\b",
        r"\b\d+\.\s+[^.\n]+(?:\n|\s)+\d+\.\s+",
    )
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in roundup_patterns):
        return False

    if extract_cves(text):
        return True

    exploit_terms = (
        r"\bactively exploited\b",
        r"\bexploited in the wild\b",
        r"\bin-the-wild exploitation\b",
        r"\bzero[- ]day\b",
        r"\b0day\b",
        r"\bremote code execution\b",
        r"\brce\b",
        r"\bprivilege escalation\b",
        r"\bauthentication bypass\b",
        r"\bexploit chain\b",
        r"\bsupply[- ]chain attack\b",
        r"\bcompromised packages?\b",
        r"\bmalicious packages?\b",
        r"\bcache poisoning\b",
        r"\bcritical vulnerability\b",
        r"\bemergency patch\b",
        r"\bsecurity advisory\b",
    )
    vulnerability_terms = (
        r"\bvulnerabilit(?:y|ies)\b",
        r"\bexploit(?:ed|s|ing|ation)?\b",
        r"\bpatched\b",
        r"\bsecurity flaw\b",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in exploit_terms) and any(
        re.search(pattern, text, re.IGNORECASE) for pattern in vulnerability_terms
    )


def parse_datetime(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed
        except Exception:
            return None


def fetch_cisa_kev(days_back: int, no_network: bool) -> list[ThreatItem]:
    if no_network:
        return []
    cutoff = utc_now() - dt.timedelta(days=days_back)
    try:
        payload = request_json(CISA_KEV_URL)
    except Exception as exc:  # noqa: BLE001
        record_source_failure("cisa-kev", f"warning: CISA KEV fetch failed: {exc}")
        return []
    items = []
    for vuln in payload.get("vulnerabilities", []) or []:
        date_added = parse_datetime(vuln.get("dateAdded"))
        if date_added and date_added < cutoff:
            continue
        cve = vuln.get("cveID")
        title = f"{cve}: {vuln.get('vendorProject', '')} {vuln.get('product', '')}".strip()
        text = " ".join(str(vuln.get(key, "")) for key in ("shortDescription", "knownRansomwareCampaignUse", "requiredAction", "notes"))
        items.append(
            ThreatItem(
                source="cisa-kev",
                title=title,
                url=CISA_KEV_URL,
                published=vuln.get("dateAdded"),
                cves=tuple([cve]) if cve else (),
                text=text,
            )
        )
    return items


def fetch_nvd_recent(days_back: int, no_network: bool) -> list[ThreatItem]:
    if no_network:
        return []
    end = utc_now()
    start = end - dt.timedelta(days=days_back)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    url = f"{NVD_CVES_URL}?{urllib.parse.urlencode(params)}"
    try:
        payload = request_json(url)
    except Exception as exc:  # noqa: BLE001
        record_source_failure("nvd-recent", f"warning: NVD recent fetch failed: {exc}")
        return []
    items: list[ThreatItem] = []
    for wrapper in payload.get("vulnerabilities", []) or []:
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = ""
        for candidate in descriptions:
            if candidate.get("lang") == "en":
                description = candidate.get("value", "")
                break
        metrics = cve.get("metrics", {})
        severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                severity = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        raw_refs = cve.get("references", [])
        if isinstance(raw_refs, dict):
            refs = raw_refs.get("referenceData", [])
        elif isinstance(raw_refs, list):
            refs = raw_refs
        else:
            refs = []
        url_ref = refs[0].get("url") if refs and isinstance(refs[0], dict) else None
        items.append(
            ThreatItem(
                source="nvd-recent",
                title=f"{cve_id}: {text_excerpt(description)}",
                url=url_ref,
                published=cve.get("published"),
                cves=tuple([cve_id]) if cve_id else (),
                text=description,
                severity=severity,
            )
        )
    return items


def xml_text(node: ET.Element, names: tuple[str, ...]) -> str | None:
    for name in names:
        found = node.find(name)
        if found is not None and found.text:
            return found.text.strip()
    return None


def fetch_rss_items(urls: list[str], days_back: int, no_network: bool) -> list[ThreatItem]:
    if no_network:
        return []
    cutoff = utc_now() - dt.timedelta(days=days_back)
    items: list[ThreatItem] = []
    for url in urls:
        try:
            text = request_text(url)
            root = ET.fromstring(text)
        except Exception as exc:  # noqa: BLE001
            source = f"rss:{urllib.parse.urlparse(url).netloc}"
            record_source_failure(source, f"warning: RSS fetch failed for {url}: {exc}")
            continue
        candidates = root.findall(".//item") or root.findall("{http://www.w3.org/2005/Atom}entry")
        for node in candidates[:40]:
            title = xml_text(node, ("title", "{http://www.w3.org/2005/Atom}title")) or "untitled"
            link = xml_text(node, ("link", "guid"))
            atom_link = node.find("{http://www.w3.org/2005/Atom}link")
            if atom_link is not None:
                link = atom_link.attrib.get("href") or link
            published = xml_text(node, ("pubDate", "published", "updated", "{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated"))
            parsed = parse_datetime(published)
            if parsed and parsed < cutoff:
                continue
            summary = xml_text(node, ("description", "summary", "{http://www.w3.org/2005/Atom}summary", "{http://www.w3.org/2005/Atom}content")) or ""
            combined = f"{title}\n{summary}"
            if not is_security_exploit_news(title, summary):
                continue
            items.append(
                ThreatItem(
                    source=f"rss:{urllib.parse.urlparse(url).netloc}",
                    title=title,
                    url=link,
                    published=published,
                    cves=extract_cves(combined),
                    text=summary,
                )
            )
    return items


def fetch_x_recent(config: dict[str, Any], no_network: bool) -> list[ThreatItem]:
    x_config = ((config.get("threat_intel") or {}).get("x_recent_search") or {})
    if no_network or not x_config.get("enabled", False):
        return []
    token = os.environ.get(x_config.get("bearer_token_env", "X_BEARER_TOKEN"))
    if not token:
        record_source_failure("x-recent", "warning: X recent search skipped; X_BEARER_TOKEN is not set")
        return []
    items: list[ThreatItem] = []
    max_results = int(x_config.get("max_results_per_query", 10))
    for query in x_config.get("queries", []) or []:
        params = {
            "query": query,
            "max_results": max(10, min(max_results, 100)),
            "tweet.fields": "created_at,author_id",
        }
        url = f"{X_RECENT_SEARCH_URL}?{urllib.parse.urlencode(params)}"
        try:
            payload = request_json(url, headers={"Authorization": f"Bearer {token}", "User-Agent": "codex-guardtower/0.1"})
        except urllib.error.HTTPError as exc:
            record_source_failure("x-recent", f"warning: X recent search failed for {query!r}: HTTP {exc.code}")
            continue
        except Exception as exc:  # noqa: BLE001
            record_source_failure("x-recent", f"warning: X recent search failed for {query!r}: {exc}")
            continue
        for tweet in payload.get("data", []) or []:
            text = tweet.get("text", "")
            if text.lstrip().startswith("@") and not extract_cves(text):
                continue
            if not is_security_exploit_news(text[:140], text):
                continue
            tweet_id = tweet.get("id")
            items.append(
                ThreatItem(
                    source="x-recent",
                    title=text_excerpt(text, limit=280),
                    url=f"https://x.com/i/web/status/{tweet_id}" if tweet_id else None,
                    published=tweet.get("created_at"),
                    cves=extract_cves(text),
                    text=text,
                )
            )
        time.sleep(1.0)
    return items


def surface_package_index(config: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for surface in config.get("watched_surfaces") or []:
        for package in surface.get("packages") or []:
            key = (str(package.get("ecosystem", "")).lower(), str(package.get("name", "")).lower())
            index.setdefault(key, []).append(surface)
    return index


def surface_name_hits(config: dict[str, Any], text: str) -> list[dict[str, Any]]:
    hits = []
    for surface in config.get("watched_surfaces") or []:
        for name in surface.get("names") or []:
            if surface_name_matches(str(name), text):
                hits.append(surface)
                break
    return hits


def surface_name_matches(name: str, text: str) -> bool:
    needle = name.strip()
    if not needle:
        return False
    escaped = re.escape(needle)
    prefix = r"(?<![A-Za-z0-9_@./-])" if needle[0].isalnum() else ""
    suffix = r"(?![A-Za-z0-9_@./-])" if needle[-1].isalnum() else ""
    pattern = re.compile(f"{prefix}{escaped}{suffix}", re.IGNORECASE)
    for match in pattern.finditer(text):
        following = text[match.end() : match.end() + 40]
        if needle.lower() == "react" and re.match(r"\s+framework\b", following, re.IGNORECASE):
            continue
        return True
    return False


def build_osv_exposures(dependencies: list[Dependency], osv_results: dict[tuple[str, str, str | None], list[dict[str, Any]]]) -> list[Exposure]:
    dep_index: dict[tuple[str, str, str | None], list[Dependency]] = {}
    for dep in dependencies:
        dep_index.setdefault((dep.ecosystem, dep.name, dep.version), []).append(dep)
    exposures: list[Exposure] = []
    for key, vulns in osv_results.items():
        for dep in dep_index.get(key, []):
            for vuln in vulns:
                aliases = vuln.get("aliases") or []
                advisory_id = vuln.get("id")
                cve = next((alias for alias in aliases if str(alias).startswith("CVE-")), None)
                exposures.append(
                    Exposure(
                        kind="direct-package",
                        severity="high",
                        source="osv",
                        project=dep.project,
                        dependency=dep,
                        title=vuln.get("summary") or vuln.get("details", "")[:140] or advisory_id,
                        advisory_id=cve or advisory_id,
                        url=f"https://osv.dev/vulnerability/{advisory_id}" if advisory_id else None,
                        evidence=f"OSV reports {advisory_id} for {dep.ecosystem}:{dep.name} {dep.version or '(any version)'}",
                    )
                )
    return exposures


def build_threat_exposures(config: dict[str, Any], dependencies: list[Dependency], threat_items: list[ThreatItem]) -> list[Exposure]:
    package_index: dict[tuple[str, str], list[Dependency]] = {}
    for dep in dependencies:
        package_index.setdefault((dep.ecosystem.lower(), dep.name.lower()), []).append(dep)
    configured_surface_packages = surface_package_index(config)
    exposures: list[Exposure] = []
    for item in threat_items:
        text = f"{item.title}\n{item.text}"
        for surface in surface_name_hits(config, text):
            direct_matches: list[Dependency] = []
            for package in surface.get("packages") or []:
                key = (str(package.get("ecosystem", "")).lower(), str(package.get("name", "")).lower())
                direct_matches.extend(package_index.get(key, []))
            if direct_matches:
                for dep in direct_matches:
                    exposures.append(
                        Exposure(
                            kind="watched-surface-package",
                            severity="medium",
                            source=item.source,
                            project=dep.project,
                            dependency=dep,
                            title=item.title,
                            advisory_id=", ".join(item.cves) if item.cves else None,
                            url=item.url,
                            evidence=f"{item.source} mentions watched surface {surface.get('id')} and project uses {dep.ecosystem}:{dep.name}",
                        )
                    )
            else:
                exposures.append(
                    Exposure(
                        kind="watched-surface-mention",
                        severity="info",
                        source=item.source,
                        project=None,
                        dependency=None,
                        title=item.title,
                        advisory_id=", ".join(item.cves) if item.cves else None,
                        url=item.url,
                        evidence=f"{item.source} mentions watched surface {surface.get('id')}; no configured package match was found locally",
                    )
                )
    return exposures


def unique_exposures(exposures: list[Exposure]) -> list[Exposure]:
    seen = set()
    output = []
    for exposure in exposures:
        dep_key = exposure.dependency.key if exposure.dependency else None
        key = (exposure.kind, exposure.project, dep_key, exposure.advisory_id, exposure.url, exposure.title)
        if key in seen:
            continue
        seen.add(key)
        output.append(exposure)
    severity_order = {"high": 0, "medium": 1, "info": 2}
    return sorted(output, key=lambda item: (severity_order.get(item.severity, 9), item.project or "", item.title))


def exposure_fingerprint_dict(exposure: dict[str, Any]) -> str:
    dep = exposure.get("dependency") or {}
    stable_advisory = exposure.get("advisory_id")
    stable_url = exposure.get("url")
    identity = {
        "kind": exposure.get("kind"),
        "source": exposure.get("source"),
        "project": exposure.get("project"),
        "ecosystem": dep.get("ecosystem"),
        "name": dep.get("name"),
        "version": dep.get("version"),
        "advisory_id": stable_advisory,
        "url": stable_url,
        "title": None if stable_advisory or stable_url else exposure.get("title"),
    }
    stable = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]


def attach_exposure_fingerprints(payload: dict[str, Any]) -> None:
    for exposure in payload.get("exposures", []):
        if isinstance(exposure, dict):
            exposure["fingerprint"] = exposure_fingerprint_dict(exposure)


def review_state_path(config: dict[str, Any]) -> Path:
    raw = (
        config.get("review_state_file")
        or (config.get("remediation_permission") or {}).get("review_state_file")
        or "~/.codex/guardtower/reviews.json"
    )
    return Path(str(raw)).expanduser()


def parse_iso_datetime(value: Any) -> dt.datetime | None:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def load_review_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text())
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = payload.get("reviews") or []
    else:
        entries = []
    return [entry for entry in entries if isinstance(entry, dict)]


def acquire_file_lock(path: Path, timeout_seconds: float = 10.0) -> tuple[int, Path]:
    lock_path = path.with_name(f"{path.name}.lock")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("utf-8"))
            return fd, lock_path
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for lock {lock_path}")
            time.sleep(0.05)


def release_file_lock(fd: int, lock_path: Path) -> None:
    os.close(fd)
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2) + "\n")
    os.replace(tmp_path, path)


def review_entry_is_current(entry: dict[str, Any], now: dt.datetime) -> bool:
    expires_at = parse_iso_datetime(entry.get("expires_at"))
    return expires_at is None or expires_at > now


def load_review_decisions(config: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], Path]:
    path = review_state_path(config)
    try:
        entries = load_review_entries(path)
    except Exception as exc:  # noqa: BLE001 - report bad local review state without aborting the scan.
        record_source_failure("review-state", f"warning: could not read review state {path}: {exc}")
        return {}, path
    now = utc_now()
    decisions: dict[str, dict[str, Any]] = {}
    for entry in entries:
        fingerprint = str(entry.get("fingerprint") or "")
        status = str(entry.get("status") or "")
        if fingerprint and status in REVIEW_STATUSES and review_entry_is_current(entry, now):
            decisions[fingerprint] = entry
    return decisions, path


def review_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: entry.get(key)
        for key in ("status", "reason", "reviewed_at", "reviewed_by", "expires_at", "request_id")
        if entry.get(key)
    }


def apply_review_state(config: dict[str, Any], payload: dict[str, Any]) -> None:
    reviews, path = load_review_decisions(config)
    raw_exposures = list(payload.get("exposures") or [])
    active_exposures: list[dict[str, Any]] = []
    reviewed_exposures: list[dict[str, Any]] = []
    for exposure in raw_exposures:
        if not isinstance(exposure, dict):
            continue
        fingerprint = exposure.get("fingerprint") or exposure_fingerprint_dict(exposure)
        exposure["fingerprint"] = fingerprint
        review = reviews.get(str(fingerprint))
        if not review:
            active_exposures.append(exposure)
            continue
        reviewed = dict(exposure)
        reviewed["review"] = review_metadata(review)
        if str(review.get("status")) in REVIEW_SUPPRESSING_STATUSES:
            reviewed_exposures.append(reviewed)
        else:
            active_exposures.append(reviewed)

    payload["all_exposures"] = raw_exposures
    payload["exposures"] = active_exposures
    payload["reviewed_exposures"] = reviewed_exposures
    payload["review_state"] = {
        "path": str(path),
        "active_reviews": len(reviews),
        "matched_reviews": len(reviewed_exposures),
    }
    summary = payload.setdefault("summary", {})
    summary["raw_exposures"] = len(raw_exposures)
    summary["reviewed_exposures"] = len(reviewed_exposures)
    summary["exposures"] = len(active_exposures)


def report_json_paths(report_dir: Path) -> list[Path]:
    return sorted(path for path in report_dir.glob("*.json") if path.is_file())


def report_is_comparable(payload: dict[str, Any], *, require_network_enabled: bool) -> bool:
    scan = payload.get("scan")
    if isinstance(scan, dict):
        return bool(scan.get("network_enabled")) if require_network_enabled else True
    summary = payload.get("summary") or {}
    if require_network_enabled and summary.get("threat_items", 0) == 0 and summary.get("exposures", 0) == 0:
        return False
    return True


def infer_exposure_source(exposure: dict[str, Any]) -> str | None:
    source = exposure.get("source")
    if source:
        return str(source)
    evidence = str(exposure.get("evidence") or "")
    if evidence.startswith("OSV reports"):
        return "osv"
    match = re.match(r"([^ ]+) mentions watched surface", evidence)
    if match:
        return match.group(1)
    return None


def load_previous_report(
    report_dir: Path,
    current_json_path: Path | None = None,
    *,
    require_network_enabled: bool,
) -> dict[str, Any] | None:
    paths = report_json_paths(report_dir)
    if current_json_path is not None:
        paths = [path for path in paths if path.resolve() != current_json_path.resolve()]
    for path in reversed(paths):
        try:
            payload = json.loads(path.read_text())
        except Exception:  # noqa: BLE001 - skip corrupted or partial reports.
            continue
        if (
            isinstance(payload, dict)
            and isinstance(payload.get("exposures"), list)
            and report_is_comparable(payload, require_network_enabled=require_network_enabled)
        ):
            return payload
    return None


def exposure_label(exposure: dict[str, Any]) -> str:
    dep = exposure.get("dependency") or {}
    package = ""
    if dep:
        package = f" {dep.get('ecosystem')}:{dep.get('name')}@{dep.get('version') or 'unknown'}"
    project = f" in {exposure.get('project')}" if exposure.get("project") else ""
    advisory = f" [{exposure.get('advisory_id')}]" if exposure.get("advisory_id") else ""
    return f"{exposure.get('severity')} {exposure.get('kind')}{project}{package}{advisory}: {exposure.get('title')}"


def normalize_path_prefix(path: str) -> str:
    return str(Path(path).expanduser().resolve())


def inventory_status_for_path(deployment_inventory: list[dict[str, Any]], manifest: str | None) -> dict[str, Any] | None:
    if not manifest:
        return None
    manifest_path = normalize_path_prefix(manifest)
    matches = []
    for item in deployment_inventory:
        prefix = item.get("path_prefix")
        if prefix and manifest_path.startswith(normalize_path_prefix(str(prefix))):
            matches.append((len(str(prefix)), item))
    if not matches:
        return None
    return sorted(matches, key=lambda value: value[0], reverse=True)[0][1]


def deployment_status_for(config: dict[str, Any], exposure: dict[str, Any], deployment_inventory: list[dict[str, Any]] | None = None) -> str:
    dep = exposure.get("dependency") or {}
    manifest = dep.get("manifest")
    project = exposure.get("project")
    if not manifest and not project:
        return "not applicable"
    for entry in config.get("deployment_status") or []:
        status = str(entry.get("status") or "unknown")
        if project and entry.get("project") == project:
            return status
        prefix = entry.get("path_prefix")
        if manifest and prefix and str(manifest).startswith(str(prefix)):
            return status
    discovered = inventory_status_for_path(deployment_inventory or [], manifest)
    if discovered:
        return str(discovered.get("status") or "unknown")
    if manifest:
        path = Path(manifest)
        for parent in [path.parent, *path.parents]:
            if parent == parent.parent:
                break
            if any((parent / marker).exists() for marker in ("vercel.json", "fly.toml", "render.yaml", "railway.json")):
                return "deployable marker found"
            if (parent / "Dockerfile").exists():
                return "container marker found"
    return "unknown"


def exposure_class_for(config: dict[str, Any], exposure: dict[str, Any], deployment_inventory: list[dict[str, Any]] | None = None) -> str:
    if not exposure.get("dependency"):
        return "unmatched intel"
    deployment_status = deployment_status_for(config, exposure, deployment_inventory)
    if deployment_status in {"deployed", "production"}:
        return "deployed"
    dep = exposure["dependency"]
    manifest = str(dep.get("manifest") or "")
    source = str(dep.get("source") or "")
    if source in {"devDependencies", "tool.poetry.dev-dependencies"} or ".dev-dependencies" in source or ".group.dev" in source or source.endswith(".develop"):
        return "dev dependency"
    if Path(manifest).name in {"package-lock.json", "npm-shrinkwrap.json", "poetry.lock", "Pipfile.lock", "Cargo.lock", "Gemfile.lock"}:
        return "lockfile-only"
    return "active repo"


def urgency_for(exposure: dict[str, Any], exposure_class: str) -> str:
    if exposure_class == "deployed":
        return "critical"
    if exposure.get("kind") == "direct-package" and exposure_class == "active repo":
        return "high"
    if exposure.get("kind") == "watched-surface-package":
        return "medium"
    if exposure_class == "lockfile-only":
        return "medium"
    if exposure_class == "dev dependency":
        return "medium"
    return "watch"


def recommended_action_for(exposure: dict[str, Any], exposure_class: str, deployment_status: str) -> str:
    dep = exposure.get("dependency") or {}
    package = ""
    if dep:
        package = f"{dep.get('ecosystem')}:{dep.get('name')}@{dep.get('version') or 'unknown'}"
    if exposure.get("kind") == "watched-surface-package":
        return f"Review whether the intel applies to {package}; if the installed version is affected, patch and rerun Guardtower."
    if exposure_class == "deployed":
        return f"Confirm runtime exposure, patch or redeploy {package}, and add a post-fix scan note."
    if exposure_class == "active repo":
        return f"Upgrade or remove {package}; rerun tests and the scanner."
    if exposure_class == "lockfile-only":
        return f"Check whether {package} is transitive/runtime; update the parent dependency or refresh the lockfile."
    if exposure_class == "dev dependency":
        return f"Update dev tooling package {package}; prioritize if CI or build artifacts consume untrusted input."
    if exposure_class == "unmatched intel":
        return "Verify whether this product/surface is used in any project or deployment; add package or deployment mapping if yes."
    return f"Review {package or 'the finding'} and classify deployment status."


def project_directory_for(exposure: dict[str, Any]) -> str:
    dep = exposure.get("dependency") or {}
    manifest = dep.get("manifest")
    if manifest:
        return str(Path(manifest).parent)
    return exposure.get("project") or "unmatched"


def vulnerability_label_for(exposure: dict[str, Any]) -> str:
    advisory = exposure.get("advisory_id")
    title = exposure.get("title") or "untitled"
    return f"{advisory}: {title}" if advisory else title


def build_action_view(config: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    deployment_inventory = payload.get("deployment_inventory") or []
    urgency_order = {"critical": 0, "high": 1, "medium": 2, "watch": 3}
    class_order = {"deployed": 0, "active repo": 1, "lockfile-only": 2, "dev dependency": 3, "unmatched intel": 4}
    for exposure in payload.get("exposures") or []:
        exposure_class = exposure_class_for(config, exposure, deployment_inventory)
        deployment_status = deployment_status_for(config, exposure, deployment_inventory)
        urgency = urgency_for(exposure, exposure_class)
        rows.append(
            {
                "urgency": urgency,
                "vulnerability": vulnerability_label_for(exposure),
                "project_directory": project_directory_for(exposure),
                "deployment_status": deployment_status,
                "severity": exposure_class,
                "recommended_action": recommended_action_for(exposure, exposure_class, deployment_status),
                "fingerprint": exposure.get("fingerprint") or exposure_fingerprint_dict(exposure),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            urgency_order.get(row["urgency"], 9),
            class_order.get(row["severity"], 9),
            row["project_directory"],
            row["vulnerability"],
        ),
    )


def urgency_rank(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "watch": 3}.get(value, 9)


def class_rank(value: str) -> int:
    return {"deployed": 0, "active repo": 1, "lockfile-only": 2, "dev dependency": 3, "unmatched intel": 4}.get(value, 9)


def package_label(dep: dict[str, Any]) -> str:
    version = dep.get("version") or "unknown"
    return f"{dep.get('ecosystem')}:{dep.get('name')}@{version}"


def package_attribution_command(dep: dict[str, Any], directory: str) -> str:
    ecosystem = str(dep.get("ecosystem") or "").lower()
    name = str(dep.get("name") or "")
    if ecosystem == "npm":
        return f"cd {directory} && npm explain {name}"
    if ecosystem == "crates.io":
        return f"cd {directory} && cargo tree -i {name}"
    if ecosystem == "pypi":
        return f"cd {directory} && pipdeptree -r -p {name}"
    if ecosystem == "go":
        return f"cd {directory} && go mod why -m {name}"
    if ecosystem == "rubygems":
        return f"cd {directory} && bundle why {name}"
    return f"cd {directory} && inspect dependency {name}"


def cluster_action_for(cluster: dict[str, Any]) -> str:
    package = cluster.get("package") or "unmatched intel"
    severity = cluster.get("severity")
    urgency = cluster.get("urgency")
    kinds = set(cluster.get("kinds") or [])
    if "direct-package" not in kinds and "watched-surface-package" in kinds:
        return f"Review whether the intel applies to {package}; if the installed version is affected, patch and rerun Guardtower."
    if severity == "deployed" or urgency == "critical":
        return f"Confirm runtime exposure for {package}, patch or pin safely, redeploy, then rerun Guardtower."
    if severity == "active repo":
        return f"Upgrade or replace {package} in affected active repos, run tests/builds, then rerun Guardtower."
    if severity == "lockfile-only":
        return f"Run attribution commands for {package}; update the parent dependency or refresh the lockfile."
    if severity == "dev dependency":
        return f"Update dev tooling dependency {package}; prioritize CI/build paths that process untrusted input."
    return "Map this intel item to a concrete package/deployment, or suppress it if not relevant."


def build_remediation_clusters(config: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, Any]]:
    deployment_inventory = payload.get("deployment_inventory") or []
    clusters: dict[tuple[Any, ...], dict[str, Any]] = {}
    for exposure in payload.get("exposures") or []:
        dep = exposure.get("dependency")
        if dep:
            key = ("package", dep.get("ecosystem"), dep.get("name"), dep.get("version") or "unknown")
            directory = project_directory_for(exposure)
            package = package_label(dep)
        else:
            key = ("intel", exposure.get("source"), exposure.get("advisory_id"), exposure.get("title"))
            directory = "unmatched"
            package = None

        exposure_class = exposure_class_for(config, exposure, deployment_inventory)
        deployment_status = deployment_status_for(config, exposure, deployment_inventory)
        urgency = urgency_for(exposure, exposure_class)
        cluster = clusters.setdefault(
            key,
            {
                "urgency": urgency,
                "package": package,
                "vulnerability": vulnerability_label_for(exposure),
                "affected_directories": set(),
                "deployment_statuses": set(),
                "severity_classes": set(),
                "advisories": set(),
                "sources": set(),
                "kinds": set(),
                "fingerprints": set(),
                "exposure_count": 0,
                "attribution_commands": set(),
            },
        )
        if urgency_rank(urgency) < urgency_rank(cluster["urgency"]):
            cluster["urgency"] = urgency
        if class_rank(exposure_class) < class_rank(next(iter(cluster["severity_classes"]), exposure_class)):
            cluster["severity"] = exposure_class
        cluster["affected_directories"].add(directory)
        cluster["deployment_statuses"].add(deployment_status)
        cluster["severity_classes"].add(exposure_class)
        cluster["sources"].add(str(exposure.get("source") or "unknown"))
        cluster["kinds"].add(str(exposure.get("kind") or "unknown"))
        if exposure.get("advisory_id"):
            for advisory in str(exposure["advisory_id"]).split(","):
                advisory = advisory.strip()
                if advisory:
                    cluster["advisories"].add(advisory)
        elif exposure.get("title"):
            cluster["advisories"].add(str(exposure["title"])[:120])
        cluster["exposure_count"] += 1
        if dep:
            cluster["attribution_commands"].add(package_attribution_command(dep, directory))
        cluster["fingerprints"].add(exposure.get("fingerprint") or exposure_fingerprint_dict(exposure))

    output = []
    for cluster in clusters.values():
        severity_classes = sorted(cluster["severity_classes"], key=class_rank)
        severity = cluster.get("severity") or (severity_classes[0] if severity_classes else "unmatched intel")
        directories = sorted(cluster["affected_directories"])
        advisories = sorted(cluster["advisories"])
        commands = sorted(cluster["attribution_commands"])
        row = {
            "urgency": cluster["urgency"],
            "package": cluster["package"] or "unmatched intel",
            "vulnerability": cluster["vulnerability"],
            "affected_directory_count": len(directories),
            "affected_directories": directories,
            "deployment_statuses": sorted(cluster["deployment_statuses"]),
            "severity": severity,
            "severity_classes": severity_classes,
            "exposure_count": cluster["exposure_count"],
            "advisory_count": len(advisories),
            "advisories": advisories,
            "sources": sorted(cluster["sources"]),
            "kinds": sorted(cluster["kinds"]),
            "fingerprints": sorted(cluster["fingerprints"]),
            "attribution_commands": commands,
        }
        row["recommended_action"] = cluster_action_for(row)
        output.append(row)

    return sorted(
        output,
        key=lambda row: (
            urgency_rank(row["urgency"]),
            class_rank(row["severity"]),
            -int(row["exposure_count"]),
            row["package"],
        ),
    )


def permission_request_id(prefix: str, cluster: dict[str, Any]) -> str:
    identity = {
        "prefix": prefix,
        "package": cluster.get("package"),
        "advisories": cluster.get("advisories") or [],
        "affected_directories": cluster.get("affected_directories") or [],
    }
    stable = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(stable.encode('utf-8')).hexdigest()[:10]}"


def build_permission_requests(config: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, Any]]:
    permission_config = config.get("remediation_permission") or {}
    if not permission_config.get("enabled", True):
        return []
    max_requests = int(permission_config.get("max_requests", 8))
    fix_urgencies = set(permission_config.get("fix_urgencies") or ["critical", "high"])
    review_urgencies = set(permission_config.get("review_urgencies") or ["critical"])
    include_review_requests = bool(permission_config.get("include_review_requests", True))
    requests: list[dict[str, Any]] = []
    for cluster in payload.get("remediation_clusters") or []:
        kinds = set(cluster.get("kinds") or [])
        urgency = str(cluster.get("urgency") or "")
        request_type = None
        prefix = None
        if "direct-package" in kinds and urgency in fix_urgencies:
            request_type = "fix"
            prefix = "GT-FIX"
        elif include_review_requests and "watched-surface-package" in kinds and urgency in review_urgencies:
            request_type = "review"
            prefix = "GT-REVIEW"
        if not request_type or not prefix:
            continue
        request_id = permission_request_id(prefix, cluster)
        package = str(cluster.get("package") or "unmatched intel")
        directories = cluster.get("affected_directories") or []
        scope = ", ".join(directories[:3])
        if len(directories) > 3:
            scope += f", and {len(directories) - 3} more"
        if request_type == "fix":
            question = (
                f"Approve {request_id} to let Codex remediate {package} in the affected repo(s), "
                "run attribution commands and tests/builds, then prepare commits or PRs. "
                "Do not deploy, mutate paid cloud jobs, or merge without separate approval."
            )
        else:
            question = (
                f"Approve {request_id} to let Codex verify whether the watched-surface intel applies to {package}, "
                "check installed versions and affected ranges, and only propose a patch if exposure is confirmed. "
                "Do not deploy, mutate paid cloud jobs, or merge without separate approval."
            )
        requests.append(
            {
                "id": request_id,
                "type": request_type,
                "urgency": urgency,
                "package": package,
                "exposure_count": cluster.get("exposure_count"),
                "affected_directory_count": cluster.get("affected_directory_count"),
                "affected_directories": directories,
                "deployment_statuses": cluster.get("deployment_statuses") or [],
                "severity": cluster.get("severity"),
                "advisories": cluster.get("advisories") or [],
                "recommended_action": cluster.get("recommended_action"),
                "attribution_commands": cluster.get("attribution_commands") or [],
                "fingerprints": cluster.get("fingerprints") or [],
                "approval_phrase": f"Approve {request_id}",
                "question": question,
                "scope": scope or "unmatched",
            }
        )
        if len(requests) >= max_requests:
            break
    return requests


def vercel_scope_params(vercel_config: dict[str, Any]) -> dict[str, str]:
    params = {}
    team_id_env = vercel_config.get("team_id_env", "VERCEL_TEAM_ID")
    team_slug_env = vercel_config.get("team_slug_env", "VERCEL_TEAM_SLUG")
    team_id = os.environ.get(team_id_env)
    team_slug = os.environ.get(team_slug_env)
    if team_id:
        params["teamId"] = team_id
    elif team_slug:
        params["slug"] = team_slug
    return params


def vercel_deployment_status(project_identifier: str, vercel_config: dict[str, Any], token: str) -> tuple[str, dict[str, Any]]:
    params = {
        "limit": "1",
        "target": "production",
        "state": "READY",
        "projectId": project_identifier,
    }
    params.update(vercel_scope_params(vercel_config))
    url = f"https://api.vercel.com/v6/deployments?{urllib.parse.urlencode(params)}"
    payload = request_json_auth(url, token)
    deployments = payload.get("deployments") or []
    if deployments:
        deployment = deployments[0]
        deployment_url = deployment.get("url")
        return "deployed", {
            "latest_deployment_url": f"https://{deployment_url}" if deployment_url and not str(deployment_url).startswith("http") else deployment_url,
            "deployment_uid": deployment.get("uid"),
            "deployment_state": deployment.get("state"),
            "deployment_target": deployment.get("target"),
        }
    return "linked; no READY production deployment found", {}


def discover_local_vercel_projects(config: dict[str, Any]) -> list[dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}
    exclude_dirs = set(config.get("exclude_dirs") or [])
    max_depth = int(config.get("max_depth", 5)) + 2
    for root in discover_scan_roots(config):
        root_depth = len(root.parts)
        for current_root, dirs, files in os.walk(root):
            current = Path(current_root)
            depth = len(current.parts) - root_depth
            if depth >= max_depth:
                dirs[:] = []
            dirs[:] = [
                dirname
                for dirname in dirs
                if dirname not in exclude_dirs
                and dirname not in {"node_modules", ".next"}
                and not dirname.endswith(".app")
            ]
            if current.name == ".vercel" and "project.json" in files:
                try:
                    payload = json.loads((current / "project.json").read_text())
                except Exception:  # noqa: BLE001
                    continue
                project_root = current.parent
                discovered[str(project_root)] = {
                    "provider": "vercel",
                    "path_prefix": str(project_root),
                    "project_id": payload.get("projectId"),
                    "org_id": payload.get("orgId"),
                    "status": "linked; production deployment unverified",
                    "evidence": ".vercel/project.json",
                }
                dirs[:] = []
            elif "vercel.json" in files:
                discovered.setdefault(
                    str(current),
                    {
                        "provider": "vercel",
                        "path_prefix": str(current),
                        "status": "deployable marker found",
                        "evidence": "vercel.json",
                    },
                )
    return list(discovered.values())


def build_deployment_inventory(config: dict[str, Any], no_network: bool) -> tuple[list[dict[str, Any]], list[str]]:
    inventory: list[dict[str, Any]] = []
    failures: list[str] = []
    discovery = config.get("deployment_discovery") or {}
    vercel_config = discovery.get("vercel") or {}
    if vercel_config.get("enabled", False):
        inventory.extend(discover_local_vercel_projects(config))
        configured_projects = vercel_config.get("projects") or []
        by_prefix = {item.get("path_prefix"): item for item in inventory if item.get("path_prefix")}
        for project in configured_projects:
            prefix = project.get("path_prefix")
            if not prefix:
                continue
            item = by_prefix.setdefault(
                prefix,
                {
                    "provider": "vercel",
                    "path_prefix": prefix,
                    "status": "configured; production deployment unverified",
                    "evidence": "deployment_discovery.vercel.projects",
                },
            )
            item.update({key: value for key, value in project.items() if value})
        inventory = list(by_prefix.values())

        token = os.environ.get(vercel_config.get("token_env", "VERCEL_TOKEN"))
        if not no_network and token:
            for item in inventory:
                if item.get("provider") != "vercel":
                    continue
                identifier = item.get("project_id") or item.get("project_name")
                if not identifier:
                    continue
                try:
                    status, metadata = vercel_deployment_status(str(identifier), vercel_config, token)
                except Exception as exc:  # noqa: BLE001
                    item["status"] = item.get("status") or "unknown"
                    item["deployment_error"] = str(exc)
                    failures.append("vercel")
                    continue
                item["status"] = status
                item.update(metadata)
                item["evidence"] = "Vercel deployments API"
        elif not no_network and inventory:
            failures.append("vercel")
            for item in inventory:
                if item.get("provider") == "vercel":
                    message = "VERCEL_TOKEN not set; production deployment unverified"
                    item["deployment_error"] = message
                    evidence = item.get("evidence")
                    item["evidence"] = f"{evidence}; {message}" if evidence else message
    return sorted(inventory, key=lambda item: str(item.get("path_prefix") or "")), sorted(set(failures))


def compute_delta(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    current_exposures = current.get("exposures", [])
    for exposure in current_exposures:
        if isinstance(exposure, dict):
            exposure["fingerprint"] = exposure_fingerprint_dict(exposure)
    if not previous:
        return {
            "previous_report": None,
            "new": len(current_exposures),
            "resolved": 0,
            "persisting": 0,
            "not_observed_due_to_source_failure": 0,
            "new_exposures": current_exposures,
            "resolved_exposures": [],
            "persisting_exposures": [],
            "not_observed_exposures": [],
        }

    previous_exposures = previous.get("exposures", [])
    for exposure in previous_exposures:
        if isinstance(exposure, dict):
            exposure["fingerprint"] = exposure_fingerprint_dict(exposure)
    previous_by_id = {
        exposure["fingerprint"]: exposure
        for exposure in previous_exposures
        if isinstance(exposure, dict) and exposure.get("fingerprint")
    }
    current_by_id = {
        exposure["fingerprint"]: exposure
        for exposure in current_exposures
        if isinstance(exposure, dict) and exposure.get("fingerprint")
    }
    new_ids = sorted(set(current_by_id) - set(previous_by_id))
    failed_sources = set(current.get("source_failures") or [])
    raw_resolved_ids = sorted(set(previous_by_id) - set(current_by_id))
    blocked_resolved_ids = [
        item
        for item in raw_resolved_ids
        if infer_exposure_source(previous_by_id[item]) in failed_sources
    ]
    resolved_ids = [
        item
        for item in raw_resolved_ids
        if item not in set(blocked_resolved_ids)
    ]
    persisting_ids = sorted(set(current_by_id) & set(previous_by_id))
    return {
        "previous_report": previous.get("generated_at"),
        "new": len(new_ids),
        "resolved": len(resolved_ids),
        "persisting": len(persisting_ids),
        "not_observed_due_to_source_failure": len(blocked_resolved_ids),
        "new_exposures": [current_by_id[item] for item in new_ids],
        "resolved_exposures": [previous_by_id[item] for item in resolved_ids],
        "persisting_exposures": [current_by_id[item] for item in persisting_ids],
        "not_observed_exposures": [previous_by_id[item] for item in blocked_resolved_ids],
    }


def add_delta_to_payload(payload: dict[str, Any], report_dir: Path, current_json_path: Path | None = None) -> None:
    attach_exposure_fingerprints(payload)
    require_network_enabled = bool((payload.get("scan") or {}).get("network_enabled"))
    previous = None
    if require_network_enabled:
        previous = load_previous_report(
            report_dir,
            current_json_path,
            require_network_enabled=True,
        )
    delta = compute_delta(payload, previous)
    payload["delta"] = delta
    payload["summary"]["new_exposures"] = delta["new"]
    payload["summary"]["resolved_exposures"] = delta["resolved"]
    payload["summary"]["persisting_exposures"] = delta["persisting"]
    payload["summary"]["not_observed_due_to_source_failure"] = delta["not_observed_due_to_source_failure"]


def markdown_report(payload: dict[str, Any]) -> str:
    lines = [
        f"# Guardtower Report - {payload['generated_at']}",
        "",
        f"- Dependencies inventoried: {payload['summary']['dependencies']}",
        f"- Projects with manifests: {payload['summary']['projects']}",
        f"- Threat intelligence items: {payload['summary']['threat_items']}",
        f"- Active exposures: {payload['summary']['exposures']}",
        f"- Reviewed exposures: {payload['summary'].get('reviewed_exposures', 0)}",
        f"- Raw exposures before review state: {payload['summary'].get('raw_exposures', payload['summary']['exposures'])}",
        f"- New since previous report: {payload['summary'].get('new_exposures', 0)}",
        f"- Resolved since previous report: {payload['summary'].get('resolved_exposures', 0)}",
        f"- Still present: {payload['summary'].get('persisting_exposures', 0)}",
        f"- Not observed because a source failed: {payload['summary'].get('not_observed_due_to_source_failure', 0)}",
        "",
    ]
    delta = payload.get("delta") or {}
    if delta:
        previous = delta.get("previous_report") or "none"
        lines.append(f"## Delta")
        lines.append(f"- Previous report: {previous}")
        lines.append(f"- New: {delta.get('new', 0)}")
        lines.append(f"- Resolved: {delta.get('resolved', 0)}")
        lines.append(f"- Still present: {delta.get('persisting', 0)}")
        lines.append(f"- Not observed because a source failed: {delta.get('not_observed_due_to_source_failure', 0)}")
        for label, key in (("New", "new_exposures"), ("Resolved", "resolved_exposures")):
            values = delta.get(key) or []
            if values:
                lines.append(f"### {label} Exposures")
                for exposure in values[: payload["max_report_items"]]:
                    lines.append(f"- {exposure_label(exposure)}")
                if len(values) > payload["max_report_items"]:
                    lines.append(f"- ... {len(values) - payload['max_report_items']} more in the JSON report.")
        lines.append("")
    if payload.get("source_failures"):
        lines.append("## Source Failures")
        for source in payload["source_failures"]:
            lines.append(f"- {source}")
        lines.append("")
    if payload.get("deployment_source_failures"):
        lines.append("## Deployment Discovery Failures")
        for source in payload["deployment_source_failures"]:
            lines.append(f"- {source}")
        lines.append("")
    if payload.get("reviewed_exposures"):
        lines.append("## Reviewed Findings")
        lines.append("These findings matched current review state and are excluded from remediation and permission requests.")
        lines.append("")
        lines.append("| Status | Vulnerability | Project/Directory | Package | Reason | Fingerprint |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for exposure in payload["reviewed_exposures"][: payload["max_report_items"]]:
            dep = exposure.get("dependency") or {}
            review = exposure.get("review") or {}
            package = package_label(dep) if dep else "unmatched intel"
            lines.append(
                "| "
                + " | ".join(
                    markdown_table_cell(value)
                    for value in (
                        review.get("status"),
                        vulnerability_label_for(exposure),
                        project_directory_for(exposure),
                        package,
                        review.get("reason"),
                        exposure.get("fingerprint"),
                    )
                )
                + " |"
            )
        if len(payload["reviewed_exposures"]) > payload["max_report_items"]:
            lines.append(f"- ... {len(payload['reviewed_exposures']) - payload['max_report_items']} more reviewed findings in the JSON report.")
        lines.append("")
    if payload.get("deployment_inventory"):
        lines.append("## Deployment Inventory")
        lines.append("| Provider | Project/Directory | Status | Evidence | Latest Deployment |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in payload["deployment_inventory"][: payload["max_report_items"]]:
            lines.append(
                "| "
                + " | ".join(
                    markdown_table_cell(value)
                    for value in (
                        item.get("provider"),
                        item.get("path_prefix"),
                        item.get("status"),
                        item.get("evidence") or item.get("deployment_error"),
                        item.get("latest_deployment_url"),
                    )
                )
                + " |"
            )
        lines.append("")
    if payload.get("remediation_clusters"):
        lines.append("## Remediation Plan")
        lines.append("| Urgency | Package | Exposure Count | Affected Directories | Deployment Status | Severity | Recommended Action | Attribution Commands |")
        lines.append("| --- | --- | ---: | ---: | --- | --- | --- | --- |")
        for row in payload["remediation_clusters"][: payload["max_report_items"]]:
            commands = "<br>".join(row.get("attribution_commands") or [])
            lines.append(
                "| "
                + " | ".join(
                    markdown_table_cell(value)
                    for value in (
                        row.get("urgency"),
                        row.get("package"),
                        row.get("exposure_count"),
                        row.get("affected_directory_count"),
                        ", ".join(row.get("deployment_statuses") or []),
                        row.get("severity"),
                        row.get("recommended_action"),
                        commands,
                    )
                )
                + " |"
            )
        if len(payload["remediation_clusters"]) > payload["max_report_items"]:
            lines.append(f"- ... {len(payload['remediation_clusters']) - payload['max_report_items']} more remediation clusters in the JSON report.")
        lines.append("")
    if payload.get("permission_requests"):
        lines.append("## Permission Requests")
        lines.append("Guardtower did not run these actions. Reply with an approval phrase to let Codex start one bounded remediation task.")
        lines.append("")
        lines.append("| ID | Type | Urgency | Package | Scope | Permission Prompt |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for row in payload["permission_requests"][: payload["max_report_items"]]:
            lines.append(
                "| "
                + " | ".join(
                    markdown_table_cell(value)
                    for value in (
                        row.get("id"),
                        row.get("type"),
                        row.get("urgency"),
                        row.get("package"),
                        row.get("scope"),
                        row.get("question"),
                    )
                )
                + " |"
            )
        lines.append("")
    if payload.get("action_view"):
        lines.append("## Action View")
        lines.append("| Urgency | Vulnerability | Project/Directory | Deployment Status | Severity | Recommended Action |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for row in payload["action_view"][: payload["max_report_items"]]:
            lines.append(
                "| "
                + " | ".join(
                    markdown_table_cell(row[key])
                    for key in (
                        "urgency",
                        "vulnerability",
                        "project_directory",
                        "deployment_status",
                        "severity",
                        "recommended_action",
                    )
                )
                + " |"
            )
        if len(payload["action_view"]) > payload["max_report_items"]:
            lines.append(f"- ... {len(payload['action_view']) - payload['max_report_items']} more action rows in the JSON report.")
        lines.append("")
    if payload["exposures"]:
        lines.append("## Exposures")
        exposure_limit = payload["max_report_items"]
        for exposure in payload["exposures"][:exposure_limit]:
            dep = exposure.get("dependency")
            package = ""
            if dep:
                package = f" `{dep['ecosystem']}:{dep['name']}@{dep.get('version') or 'unknown'}`"
            project = f" in `{exposure['project']}`" if exposure.get("project") else ""
            lines.append(f"- **{exposure['severity']}** {exposure['kind']}{project}{package}: {exposure['title']}")
            if exposure.get("advisory_id"):
                lines.append(f"  - Advisory: `{exposure['advisory_id']}`")
            if exposure.get("url"):
                lines.append(f"  - URL: {exposure['url']}")
            lines.append(f"  - Evidence: {exposure['evidence']}")
        if len(payload["exposures"]) > exposure_limit:
            lines.append(f"- ... {len(payload['exposures']) - exposure_limit} more exposures in the JSON report.")
        lines.append("")
    else:
        lines.append("No direct or watched-surface exposures were found.")
        lines.append("")
    if payload["parser_errors"]:
        lines.append("## Parser Warnings")
        for error in payload["parser_errors"][:25]:
            lines.append(f"- {error}")
        lines.append("")
    if payload["threat_items"]:
        lines.append("## Current Threat Items")
        for item in payload["threat_items"][: payload["max_report_items"]]:
            cves = f" ({', '.join(item['cves'])})" if item["cves"] else ""
            url = f" - {item['url']}" if item.get("url") else ""
            lines.append(f"- `{item['source']}` {item['title']}{cves}{url}")
        lines.append("")
    return "\n".join(lines)


def dataclass_to_dict(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    raise TypeError(f"Cannot serialize {type(value)!r}")


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload, default=dataclass_to_dict))


def markdown_table_cell(value: Any) -> str:
    text = str(value or "")
    text = text.replace("|", "\\|").replace("\n", " ")
    return text


def write_reports(config: dict[str, Any], payload: dict[str, Any]) -> tuple[Path, Path]:
    report_dir = Path(config.get("report_dir", "~/.codex/guardtower/reports")).expanduser()
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().strftime("%Y-%m-%dT%H%M%SZ")
    json_path = report_dir / f"{stamp}.json"
    md_path = report_dir / f"{stamp}.md"
    normalized = normalize_payload(payload)
    payload.clear()
    payload.update(normalized)
    attach_exposure_fingerprints(payload)
    apply_review_state(config, payload)
    add_delta_to_payload(payload, report_dir, current_json_path=json_path)
    payload["action_view"] = build_action_view(config, payload)
    payload["remediation_clusters"] = build_remediation_clusters(config, payload)
    payload["permission_requests"] = build_permission_requests(config, payload)
    json_path.write_text(json.dumps(payload, indent=2) + "\n")
    loaded = json.loads(json_path.read_text())
    md_path.write_text(markdown_report(loaded))
    return json_path, md_path


def report_exposures_for_review(report: dict[str, Any]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for key in ("all_exposures", "exposures", "reviewed_exposures"):
        for exposure in report.get(key) or []:
            if not isinstance(exposure, dict):
                continue
            fingerprint = exposure.get("fingerprint") or exposure_fingerprint_dict(exposure)
            if fingerprint in seen:
                continue
            seen.add(str(fingerprint))
            exposure = dict(exposure)
            exposure["fingerprint"] = fingerprint
            output.append(exposure)
    return output


def advisory_set(value: Any) -> set[str]:
    if not value:
        return set()
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = value
    return {str(item).strip() for item in values if str(item).strip()}


def exposure_matches_permission_request(exposure: dict[str, Any], request: dict[str, Any]) -> bool:
    dep = exposure.get("dependency") or {}
    if dep and request.get("package") and package_label(dep) != request.get("package"):
        return False
    directories = set(request.get("affected_directories") or [])
    if directories and project_directory_for(exposure) not in directories:
        return False
    requested_advisories = advisory_set(request.get("advisories"))
    if requested_advisories and not (requested_advisories & advisory_set(exposure.get("advisory_id"))):
        return False
    return True


def review_fingerprints_from_report(
    report: dict[str, Any],
    *,
    request_id: str | None,
    explicit_fingerprints: list[str] | None,
) -> tuple[list[str], str | None]:
    if explicit_fingerprints:
        return sorted(set(explicit_fingerprints)), request_id
    if not request_id:
        raise ValueError("provide --request-id or at least one --fingerprint")
    request = next((item for item in report.get("permission_requests") or [] if item.get("id") == request_id), None)
    if not request:
        raise ValueError(f"request id not found in report: {request_id}")
    fingerprints = [str(item) for item in request.get("fingerprints") or [] if item]
    if fingerprints:
        return sorted(set(fingerprints)), request_id
    exposures = report_exposures_for_review(report)
    matched = [
        str(exposure["fingerprint"])
        for exposure in exposures
        if exposure_matches_permission_request(exposure, request)
    ]
    if not matched:
        raise ValueError(f"no exposures matched request id: {request_id}")
    return sorted(set(matched)), request_id


def review_snapshot(exposure: dict[str, Any] | None) -> dict[str, Any]:
    if not exposure:
        return {}
    dep = exposure.get("dependency") or {}
    return {
        "kind": exposure.get("kind"),
        "project": exposure.get("project"),
        "package": package_label(dep) if dep else None,
        "manifest": dep.get("manifest") if dep else None,
        "advisory_id": exposure.get("advisory_id"),
        "title": exposure.get("title"),
        "url": exposure.get("url"),
    }


def record_review_decision(
    config: dict[str, Any],
    report_path: Path,
    *,
    request_id: str | None,
    explicit_fingerprints: list[str] | None,
    status: str,
    reason: str,
    reviewed_by: str,
    expires_at: str | None,
) -> tuple[Path, int]:
    report = json.loads(report_path.read_text())
    fingerprints, resolved_request_id = review_fingerprints_from_report(
        report,
        request_id=request_id,
        explicit_fingerprints=explicit_fingerprints,
    )
    path = review_state_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd, lock_path = acquire_file_lock(path)
    try:
        existing_entries = load_review_entries(path)
        by_fingerprint = {
            str(entry.get("fingerprint")): entry
            for entry in existing_entries
            if entry.get("fingerprint")
        }
        exposures = {str(item["fingerprint"]): item for item in report_exposures_for_review(report)}
        reviewed_at = iso_date(utc_now())
        for fingerprint in fingerprints:
            by_fingerprint[fingerprint] = {
                "fingerprint": fingerprint,
                "status": status,
                "reason": reason,
                "reviewed_at": reviewed_at,
                "reviewed_by": reviewed_by,
                "expires_at": expires_at,
                "request_id": resolved_request_id,
                "source_report": str(report_path),
                "exposure": review_snapshot(exposures.get(fingerprint)),
            }
        payload = {
            "version": 1,
            "updated_at": reviewed_at,
            "reviews": sorted(by_fingerprint.values(), key=lambda entry: str(entry.get("fingerprint") or "")),
        }
        write_json_atomic(path, payload)
    finally:
        release_file_lock(lock_fd, lock_path)
    return path, len(fingerprints)


def build_report(config: dict[str, Any], no_network: bool) -> tuple[dict[str, Any], list[Exposure]]:
    SOURCE_FAILURES.clear()
    dependencies, parser_errors = inventory_dependencies(config)
    intel_config = config.get("threat_intel") or {}
    days_back = int(intel_config.get("days_back", 3))
    osv_results = fetch_osv_vulnerabilities(
        dependencies,
        no_network or not intel_config.get("include_osv", True),
        query_versionless=bool(intel_config.get("osv_query_versionless", False)),
    )
    threat_items: list[ThreatItem] = []
    if intel_config.get("include_cisa_kev", True):
        threat_items.extend(fetch_cisa_kev(days_back, no_network))
    if intel_config.get("include_nvd_recent", True):
        threat_items.extend(fetch_nvd_recent(days_back, no_network))
    if intel_config.get("include_rss", True):
        threat_items.extend(fetch_rss_items(intel_config.get("rss_urls") or [], days_back, no_network))
    threat_items.extend(fetch_x_recent(config, no_network))
    exposures = unique_exposures(
        build_osv_exposures(dependencies, osv_results)
        + build_threat_exposures(config, dependencies, threat_items)
    )
    deployment_inventory, deployment_failures = build_deployment_inventory(config, no_network)
    projects = sorted({dep.project for dep in dependencies})
    payload = {
        "generated_at": iso_date(utc_now()),
        "scan": {
            "network_enabled": not no_network,
        },
        "summary": {
            "dependencies": len(dependencies),
            "projects": len(projects),
            "threat_items": len(threat_items),
            "exposures": len(exposures),
        },
        "projects": projects,
        "dependencies": dependencies,
        "threat_items": threat_items,
        "exposures": exposures,
        "deployment_inventory": deployment_inventory,
        "deployment_source_failures": deployment_failures,
        "source_failures": sorted(SOURCE_FAILURES),
        "parser_errors": parser_errors,
        "max_report_items": int((config.get("alert") or {}).get("max_report_items", 50)),
    }
    return payload, exposures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--no-network", action="store_true", help="Skip OSV, CISA, NVD, RSS, and X calls.")
    parser.add_argument("--record-review", type=Path, help="Record a review decision from an existing report JSON and exit.")
    parser.add_argument("--request-id", help="Permission request id to mark reviewed.")
    parser.add_argument("--fingerprint", action="append", help="Exposure fingerprint to mark reviewed. Can be repeated.")
    parser.add_argument("--review-status", choices=REVIEW_STATUSES, default="not_affected")
    parser.add_argument("--reason", help="Human-readable reason for the review decision.")
    parser.add_argument("--reviewed-by", default="codex")
    parser.add_argument("--expires-at", help="Optional ISO timestamp after which this review decision no longer applies.")
    args = parser.parse_args()

    config = load_config(args.config)
    if config.get("env_file"):
        load_env_file(Path(config["env_file"]).expanduser())
    if args.record_review:
        if not args.reason:
            parser.error("--reason is required with --record-review")
        path, count = record_review_decision(
            config,
            args.record_review,
            request_id=args.request_id,
            explicit_fingerprints=args.fingerprint,
            status=args.review_status,
            reason=args.reason,
            reviewed_by=args.reviewed_by,
            expires_at=args.expires_at,
        )
        print(f"Recorded {count} review decision(s) in {path}")
        return 0
    payload, exposures = build_report(config, args.no_network)
    json_path, md_path = write_reports(config, payload)
    print(f"Wrote JSON report: {json_path}")
    print(f"Wrote Markdown report: {md_path}")
    print(json.dumps(payload["summary"], indent=2))
    delta = payload.get("delta") or {}
    if delta:
        print(
            "Delta: "
            f"{delta.get('new', 0)} new, "
            f"{delta.get('resolved', 0)} resolved, "
            f"{delta.get('persisting', 0)} still present, "
            f"{delta.get('not_observed_due_to_source_failure', 0)} not observed due to source failure"
        )
    direct = [
        item
        for item in payload.get("exposures", [])
        if item.get("kind") in {"direct-package", "watched-surface-package"}
    ]
    if direct:
        print("Direct/package-linked exposures:")
        for exposure in direct[:20]:
            dep = exposure.get("dependency") or {}
            package = f"{dep.get('ecosystem')}:{dep.get('name')}@{dep.get('version') or 'unknown'}" if dep else ""
            print(f"- {exposure.get('severity')} {exposure.get('project') or '-'} {package}: {exposure.get('title')}")
    if (config.get("alert") or {}).get("exit_nonzero_on_direct_match") and direct:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
