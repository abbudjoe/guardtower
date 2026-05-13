#!/usr/bin/env python3
"""Daily vulnerability intelligence and local exposure scanner."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import email.utils
import json
import os
import re
import sys
import time
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
    project: str | None
    dependency: Dependency | None
    title: str
    advisory_id: str | None
    url: str | None
    evidence: str


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return json.load(handle)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_date(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()


def request_json(url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> Any:
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {"User-Agent": "codex-vuln-watch/0.1"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def request_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "codex-vuln-watch/0.1"})
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


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
    match = re.search(r"(?:==|=)\s*([A-Za-z0-9_.!+\-]+)", value)
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
            payload = request_json(OSV_QUERY_BATCH_URL, headers={"Content-Type": "application/json", "User-Agent": "codex-vuln-watch/0.1"}, data=data)
        except Exception as exc:  # noqa: BLE001
            print(f"warning: OSV query failed: {exc}", file=sys.stderr)
            continue
        for (key, _query), result in zip(chunk, payload.get("results", []), strict=False):
            vulns = result.get("vulns") if isinstance(result, dict) else None
            if vulns:
                results[key] = vulns
        time.sleep(0.2)
    return results


def extract_cves(text: str) -> tuple[str, ...]:
    return tuple(sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)), key=str.upper))


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
        print(f"warning: CISA KEV fetch failed: {exc}", file=sys.stderr)
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
        print(f"warning: NVD recent fetch failed: {exc}", file=sys.stderr)
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
                title=f"{cve_id}: {description[:140]}",
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
            print(f"warning: RSS fetch failed for {url}: {exc}", file=sys.stderr)
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
            if not re.search(r"(CVE-|vulnerab|exploit|zero.day|0day|supply chain|ransomware|advisory)", combined, re.IGNORECASE):
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
        print("warning: X recent search skipped; X_BEARER_TOKEN is not set", file=sys.stderr)
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
            payload = request_json(url, headers={"Authorization": f"Bearer {token}", "User-Agent": "codex-vuln-watch/0.1"})
        except urllib.error.HTTPError as exc:
            print(f"warning: X recent search failed for {query!r}: HTTP {exc.code}", file=sys.stderr)
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"warning: X recent search failed for {query!r}: {exc}", file=sys.stderr)
            continue
        for tweet in payload.get("data", []) or []:
            text = tweet.get("text", "")
            tweet_id = tweet.get("id")
            items.append(
                ThreatItem(
                    source="x-recent",
                    title=text[:140].replace("\n", " "),
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
    haystack = text.lower()
    hits = []
    for surface in config.get("watched_surfaces") or []:
        for name in surface.get("names") or []:
            needle = str(name).lower()
            if needle and needle in haystack:
                hits.append(surface)
                break
    return hits


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


def markdown_report(payload: dict[str, Any]) -> str:
    lines = [
        f"# Vuln Watch Report - {payload['generated_at']}",
        "",
        f"- Dependencies inventoried: {payload['summary']['dependencies']}",
        f"- Projects with manifests: {payload['summary']['projects']}",
        f"- Threat intelligence items: {payload['summary']['threat_items']}",
        f"- Exposures: {payload['summary']['exposures']}",
        "",
    ]
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


def write_reports(config: dict[str, Any], payload: dict[str, Any]) -> tuple[Path, Path]:
    report_dir = Path(config.get("report_dir", "~/.codex/vuln-watch/reports")).expanduser()
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().strftime("%Y-%m-%dT%H%M%SZ")
    json_path = report_dir / f"{stamp}.json"
    md_path = report_dir / f"{stamp}.md"
    json_path.write_text(json.dumps(payload, indent=2, default=dataclass_to_dict) + "\n")
    loaded = json.loads(json_path.read_text())
    md_path.write_text(markdown_report(loaded))
    return json_path, md_path


def build_report(config: dict[str, Any], no_network: bool) -> tuple[dict[str, Any], list[Exposure]]:
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
    projects = sorted({dep.project for dep in dependencies})
    payload = {
        "generated_at": iso_date(utc_now()),
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
        "parser_errors": parser_errors,
        "max_report_items": int((config.get("alert") or {}).get("max_report_items", 50)),
    }
    return payload, exposures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--no-network", action="store_true", help="Skip OSV, CISA, NVD, RSS, and X calls.")
    args = parser.parse_args()

    config = load_config(args.config)
    payload, exposures = build_report(config, args.no_network)
    json_path, md_path = write_reports(config, payload)
    print(f"Wrote JSON report: {json_path}")
    print(f"Wrote Markdown report: {md_path}")
    print(json.dumps(payload["summary"], indent=2))
    direct = [item for item in exposures if item.kind in {"direct-package", "watched-surface-package"}]
    if direct:
        print("Direct/package-linked exposures:")
        for exposure in direct[:20]:
            dep = exposure.dependency
            package = f"{dep.ecosystem}:{dep.name}@{dep.version or 'unknown'}" if dep else ""
            print(f"- {exposure.severity} {exposure.project or '-'} {package}: {exposure.title}")
    if (config.get("alert") or {}).get("exit_nonzero_on_direct_match") and direct:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
