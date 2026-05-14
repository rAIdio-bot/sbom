#!/usr/bin/env python3
"""
sbom_enrich.py — enrich a CycloneDX 1.5 SBOM with verbatim license texts
and copyright notices harvested from source artifacts.

Produces three artifacts at the sbom repo root:
  - sbom.json           canonical enriched SBOM (CycloneDX 1.5)
  - NOTICES.txt         plain-text rendering derived from sbom.json
  - enrich-report.txt   processing summary (counts, per-component failures)
  - drift-report.txt    license-mismatch queue (drives push.ps1 gate)

Source dispatch is category-aware via the `raidio:category` property:
  Rust Crates              -> crates.io tarball
  NPM Packages             -> npm registry tarball
  Python Packages          -> PyPI sdist (wheel fallback)
  AI Models                -> Hugging Face (memescreamer mirror)
  ComfyUI Nodes            -> GitHub raw (memescreamer or rAIdio-bot)
  Embedded Python Overrides-> GitHub raw (rAIdio-bot/rAIdio-nodes)
  System Tools             -> manual curation map (sbom_enrich_system_tools.json)

Stdlib-only (urllib, tarfile, zipfile, json, re, base64) to match the style
of generate_sbom.py and generate_cyclonedx.py.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEM_TOOLS_MAP_PATH = REPO_ROOT / "tools" / "sbom_enrich_system_tools.json"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "raidio-sbom-enrich"

# Network knobs
HTTP_TIMEOUT_S = 30
HTTP_RETRIES = 3
HTTP_BACKOFF_BASE_S = 2

# Probe order for HF / GitHub-raw single-file LICENSE fetches
LICENSE_NAME_PROBES = [
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "license",
    "license.md",
    "license.txt",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
    "LICENCE",
    "LICENCE.md",
    "LICENCE.txt",
    "NOTICE",
    "NOTICE.md",
    "NOTICE.txt",
]

# Regex matching LICENSE-like filenames inside tarballs/zips
LICENSE_FILE_RE = re.compile(
    r"(?i)(?:^|/)(LICEN[SC]E|COPYING|NOTICE|COPYRIGHT)([._-]\S*)?$"
)

# Copyright extraction — handles ©, (c), (C), word "Copyright", year ranges,
# year-only headers ("2020,2021,2022 Author") and trailing email.
# DOTALL not set, so `.` doesn't span lines; the year and name must be on
# the same logical line after whitespace-collapse.
COPYRIGHT_RE = re.compile(
    r"(?:Copyright\s*(?:\([cC]\)|©)?|©|\([cC]\))"
    r"\s+\d{4}(?:[\s,\-]+\d{2,4})*"
    r"\s+[A-Za-z][^\r\n]{2,200}"
)

# Sanitization patterns — strip absolute paths and private refs from any text
# written into the SBOM body. Defensive; should never trip in practice.
SANITIZE_PATTERNS = [
    re.compile(r"[A-Z]:\\[^\s'\"]*", re.IGNORECASE),  # C:\, D:\ Windows abs
    re.compile(r"/home/[^\s'\"]*"),
    re.compile(r"/Users/[^\s'\"]*"),
    re.compile(r"/mnt/[^\s'\"]*"),
    re.compile(r"/root/[^\s'\"]*"),
]
# Additional patterns can be appended at runtime from a local config so the
# script can sit in a public repo without literally naming what it's
# defending against. One pattern per line; lines starting with `#` are
# comments. File location is intentionally per-user so each contributor
# can carry their own defensive set.
_LOCAL_PATTERNS_CONFIG = Path.home() / ".raidio-sbom-enrich-extra-patterns.txt"
if _LOCAL_PATTERNS_CONFIG.exists():
    for raw in _LOCAL_PATTERNS_CONFIG.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw and not raw.startswith("#"):
            try:
                SANITIZE_PATTERNS.append(re.compile(raw))
            except re.error:
                pass


# ---------------------------------------------------------------------------
# IO + cache
# ---------------------------------------------------------------------------


def _cache_key(parts: tuple[str, ...]) -> str:
    joined = "|".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def http_get(url: str) -> bytes:
    """GET with retries. Raises on permanent failure."""
    last_err: Optional[Exception] = None
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "raidio-sbom-enrich/1.0"},
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=ctx) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            # 4xx are permanent; 5xx may be transient
            if 400 <= e.code < 500:
                raise
            last_err = e
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
        if attempt + 1 < HTTP_RETRIES:
            time.sleep(HTTP_BACKOFF_BASE_S * (2**attempt))
    if last_err is not None:
        raise last_err
    raise RuntimeError(f"http_get failed for {url} with no captured exception")


def cached_fetch(url: str, cache_dir: Path, no_cache: bool = False) -> bytes:
    """Content-addressable cache by URL. Immutable; one-time fetch per URL."""
    key = _cache_key((url,))
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / key
    if not no_cache and cache_path.exists():
        return cache_path.read_bytes()
    data = http_get(url)
    cache_path.write_bytes(data)
    return data


# ---------------------------------------------------------------------------
# Component classification + URL extraction
# ---------------------------------------------------------------------------


def get_category(component: dict) -> str:
    for p in component.get("properties", []):
        if p.get("name") == "raidio:category":
            return p.get("value", "")
    return ""


def get_homepage(component: dict) -> str:
    for r in component.get("externalReferences", []):
        if r.get("type") == "website":
            return r.get("url", "")
    return ""


def get_license_info(component: dict) -> dict:
    """Return {kind: "id"|"name"|"expression"|"none", value: str, all_ids: [str]}.
    `all_ids` is the parsed list of SPDX ids when kind == "expression"."""
    for lic in component.get("licenses", []):
        if "license" in lic:
            inner = lic["license"]
            if "id" in inner:
                return {"kind": "id", "value": inner["id"], "all_ids": [inner["id"]]}
            if "name" in inner:
                return {"kind": "name", "value": inner["name"], "all_ids": []}
        if "expression" in lic:
            expr = lic["expression"]
            ids = _parse_spdx_expression(expr)
            return {"kind": "expression", "value": expr, "all_ids": ids}
    return {"kind": "none", "value": "", "all_ids": []}


def _parse_spdx_expression(expr: str) -> list[str]:
    """Extract bare SPDX ids from an SPDX-expression string. Handles
    AND / OR / WITH joiners and parentheses. WITH exceptions are kept
    attached to their parent id for now (good enough for probe matching)."""
    # Strip parens; split on AND/OR keywords (case-insensitive)
    cleaned = expr.replace("(", " ").replace(")", " ")
    tokens = re.split(r"\s+(?:AND|OR)\s+", cleaned, flags=re.IGNORECASE)
    ids = [t.strip() for t in tokens if t.strip()]
    return ids


# ---------------------------------------------------------------------------
# Source dispatcher — one resolver per category
# ---------------------------------------------------------------------------


def resolve_rust_crate(name: str, version: str) -> dict:
    return {
        "kind": "tarball",
        "format": "tar.gz",
        "url": f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/download",
        "path_prefix": f"{name}-{version}/",
    }


def resolve_npm_package(name: str, version: str) -> dict:
    # Use npm registry metadata endpoint to get exact tarball URL.
    # Handles scoped packages (@scope/name) naturally.
    encoded = name.replace("/", "%2F") if name.startswith("@") else name
    return {
        "kind": "npm-via-metadata",
        "format": "tar.gz",
        "metadata_url": f"https://registry.npmjs.org/{encoded}/{urllib.parse.quote(version)}",
        # NPM tarballs unpack with a top-level "package/" directory
        "path_prefix": "package/",
    }


def resolve_python_package(name: str, version: str, homepage: str) -> dict:
    return {
        "kind": "pypi-via-metadata",
        "format": "auto",  # sdist preferred, wheel fallback
        "metadata_url": f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json",
        "homepage_fallback": homepage,
    }


def resolve_hf_model(component: dict) -> dict:
    homepage = get_homepage(component)
    m = re.match(r"https?://huggingface\.co/([^/]+)/([^/?#]+)", homepage)
    if not m:
        return {"kind": "none", "reason": f"HF URL not parseable: {homepage}"}
    owner, repo = m.group(1), m.group(2)
    revision = component.get("version", "main")
    return {
        "kind": "hf-probe",
        "owner": owner,
        "repo": repo,
        "revision": revision,
        "base_url": f"https://huggingface.co/{owner}/{repo}/resolve/{revision}",
    }


def resolve_github_raw(component: dict) -> dict:
    homepage = get_homepage(component)
    # Handle URLs with optional /tree/<ref> path (e.g. memescreamer/libsndfile/tree/1.2.2)
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/?#]+)(?:/tree/([^/?#]+))?", homepage
    )
    if not m:
        return {"kind": "none", "reason": f"GitHub URL not parseable: {homepage}"}
    owner, repo = m.group(1), m.group(2)
    revision = m.group(3) or component.get("version", "main")
    return {
        "kind": "gh-raw-probe",
        "owner": owner,
        "repo": repo,
        "revision": revision,
        "base_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{revision}",
    }


def resolve_system_tool(name: str, version: str, sys_tools_map: dict) -> dict:
    key = f"{name}@{version}"
    entry = sys_tools_map.get(key)
    if entry is None:
        return {"kind": "none", "reason": f"No curation entry for {key}"}
    return {
        "kind": "system-curated",
        "url": entry["source_tarball"],
        "path_prefix": entry.get("tarball_root_prefix", ""),
        "license_files": entry["license_files_in_tarball"],
        "notice_files": entry.get("notice_files_in_tarball", []),
        "primary_license_id": entry.get("primary_license_id", ""),
        "copyright_seed": entry.get("copyright_seed", []),
    }


def dispatch(component: dict, sys_tools_map: dict) -> dict:
    cat = get_category(component)
    name = component["name"]
    version = component["version"]
    if cat == "Rust Crates":
        return resolve_rust_crate(name, version)
    if cat == "NPM Packages":
        return resolve_npm_package(name, version)
    if cat == "Python Packages":
        return resolve_python_package(name, version, get_homepage(component))
    if cat == "AI Models":
        return resolve_hf_model(component)
    if cat in ("ComfyUI Nodes", "Embedded Python Overrides"):
        return resolve_github_raw(component)
    if cat == "System Tools":
        return resolve_system_tool(name, version, sys_tools_map)
    return {"kind": "none", "reason": f"Unknown category: {cat}"}


# ---------------------------------------------------------------------------
# Source-artifact downloaders
# ---------------------------------------------------------------------------


def fetch_tarball_license_files(
    url: str, path_prefix: str, cache_dir: Path, no_cache: bool, fmt: str = "tar.gz"
) -> dict[str, bytes]:
    """Download a tarball, extract files matching LICENSE_FILE_RE. Returns
    {relative_path: content_bytes}. tar.gz, tar, and zip supported."""
    blob = cached_fetch(url, cache_dir, no_cache)
    found: dict[str, bytes] = {}
    try:
        if fmt == "zip" or url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    rel = info.filename
                    if path_prefix and rel.startswith(path_prefix):
                        rel_strip = rel[len(path_prefix) :]
                    else:
                        rel_strip = rel
                    if LICENSE_FILE_RE.search(rel_strip):
                        try:
                            found[rel_strip] = zf.read(info.filename)
                        except Exception:
                            pass
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    rel = member.name
                    if path_prefix and rel.startswith(path_prefix):
                        rel_strip = rel[len(path_prefix) :]
                    else:
                        rel_strip = rel
                    if LICENSE_FILE_RE.search(rel_strip):
                        f = tf.extractfile(member)
                        if f is not None:
                            found[rel_strip] = f.read()
    except (tarfile.TarError, zipfile.BadZipFile) as e:
        raise RuntimeError(f"Archive open failed for {url}: {e}") from e
    return found


def fetch_tarball_source_headers(
    url: str, path_prefix: str, cache_dir: Path, no_cache: bool, fmt: str = "tar.gz", max_files: int = 100, max_lines: int = 50
) -> list[str]:
    """Read top-N lines of up to M source-looking files in the tarball.
    Returns a list of concatenated header blobs for copyright harvesting."""
    blob = cached_fetch(url, cache_dir, no_cache)
    source_exts = re.compile(
        r"\.(rs|py|js|ts|svelte|c|cc|cpp|h|hpp|go|java|rb|php|sh)$", re.IGNORECASE
    )
    headers: list[str] = []
    try:
        if fmt == "zip" or url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir() and source_exts.search(i.filename)]
                for info in infos[:max_files]:
                    try:
                        head = zf.read(info.filename).decode("utf-8", errors="replace").splitlines()[:max_lines]
                        headers.append("\n".join(head))
                    except Exception:
                        pass
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                infos = [m for m in tf.getmembers() if m.isfile() and source_exts.search(m.name)]
                for member in infos[:max_files]:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    try:
                        head = f.read().decode("utf-8", errors="replace").splitlines()[:max_lines]
                        headers.append("\n".join(head))
                    except Exception:
                        pass
    except (tarfile.TarError, zipfile.BadZipFile):
        pass
    return headers


def fetch_single_file_probes(
    base_url: str, cache_dir: Path, no_cache: bool, names: list[str] = LICENSE_NAME_PROBES
) -> dict[str, bytes]:
    """Probe a list of LICENSE-named files at base_url. Returns whichever
    succeed. Used for HF + GitHub-raw single-file dispatch."""
    found: dict[str, bytes] = {}
    for name in names:
        url = f"{base_url}/{name}"
        try:
            content = cached_fetch(url, cache_dir, no_cache)
            # Reject empty, HTML 404 pages, or anything suspicious-tiny
            if not content or len(content) < 50:
                continue
            head = content[:1024].decode("utf-8", errors="replace").lower()
            if "<html" in head or "<!doctype" in head:
                continue
            found[name] = content
        except urllib.error.HTTPError:
            continue
        except urllib.error.URLError:
            continue
    return found


def fetch_npm_via_metadata(metadata_url: str, path_prefix: str, cache_dir: Path, no_cache: bool) -> dict[str, bytes]:
    meta = json.loads(cached_fetch(metadata_url, cache_dir, no_cache))
    tarball_url = meta.get("dist", {}).get("tarball")
    if not tarball_url:
        raise RuntimeError(f"npm metadata has no dist.tarball: {metadata_url}")
    return fetch_tarball_license_files(tarball_url, path_prefix, cache_dir, no_cache)


def fetch_pypi_via_metadata(metadata_url: str, cache_dir: Path, no_cache: bool) -> dict[str, bytes]:
    meta = json.loads(cached_fetch(metadata_url, cache_dir, no_cache))
    urls = meta.get("urls", []) or meta.get("releases", {}).get(meta.get("info", {}).get("version", ""), [])
    sdist_url = None
    wheel_url = None
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            sdist_url = entry.get("url")
        elif entry.get("packagetype") == "bdist_wheel" and wheel_url is None:
            wheel_url = entry.get("url")
    target_url = sdist_url or wheel_url
    if not target_url:
        raise RuntimeError(f"PyPI metadata has no sdist or wheel: {metadata_url}")
    # sdist is .tar.gz; wheel is .whl (zip)
    fmt = "zip" if target_url.endswith(".whl") else "tar.gz"
    # PyPI sdists unpack to <name>-<version>/; wheels unpack flat. Don't pre-strip.
    return fetch_tarball_license_files(target_url, "", cache_dir, no_cache, fmt=fmt)


# ---------------------------------------------------------------------------
# License text + copyright harvest
# ---------------------------------------------------------------------------


SPDX_CANONICAL_CACHE: dict[str, str] = {}


def fetch_spdx_canonical(spdx_id: str, cache_dir: Path, no_cache: bool) -> Optional[str]:
    """Fetch the canonical text for an SPDX license id from spdx.org. Returns
    None on 404 (id not in SPDX database)."""
    if spdx_id in SPDX_CANONICAL_CACHE:
        return SPDX_CANONICAL_CACHE[spdx_id]
    # WITH exceptions: strip the exception, fetch the base license
    base_id = spdx_id.split(" WITH ")[0].strip()
    url = f"https://spdx.org/licenses/{base_id}.txt"
    try:
        content = cached_fetch(url, cache_dir, no_cache).decode("utf-8", errors="replace")
        SPDX_CANONICAL_CACHE[spdx_id] = content
        return content
    except urllib.error.HTTPError:
        return None
    except urllib.error.URLError:
        return None


def looks_like_license_text(text: str) -> bool:
    """Reject obvious garbage / HTML 404 pages."""
    if not text or len(text) < 200:
        return False
    head = text[:500].lower()
    if "<html" in head or "<!doctype" in head:
        return False
    if not any(kw in head for kw in ("permission", "license", "copyright", "redistribut", "warranty")):
        # SPDX canonical text contains "License" near the top almost always
        return False
    return True


def select_license_text(
    license_files: dict[str, bytes],
    license_info: dict,
    cache_dir: Path,
    no_cache: bool,
) -> tuple[str, str]:
    """Pick the license body for this component. Returns (text, source_tag).

    source_tag is one of: "matched", "spdx-canonical-fallback",
    "longest-file", "concatenated-dual", "unresolvable"."""
    if not license_files:
        # No tarball/probe content — try SPDX canonical
        if license_info["kind"] in ("id", "expression"):
            for sid in (license_info["all_ids"] or [license_info["value"]]):
                canon = fetch_spdx_canonical(sid, cache_dir, no_cache)
                if canon and looks_like_license_text(canon):
                    return canon, "spdx-canonical-fallback"
        return "", "unresolvable"

    decoded: dict[str, str] = {}
    for name, blob in license_files.items():
        try:
            decoded[name] = blob.decode("utf-8", errors="replace")
        except Exception:
            continue
    decoded = {n: t for n, t in decoded.items() if looks_like_license_text(t)}
    if not decoded:
        # All files suspicious — try SPDX canonical
        if license_info["kind"] in ("id", "expression"):
            for sid in (license_info["all_ids"] or [license_info["value"]]):
                canon = fetch_spdx_canonical(sid, cache_dir, no_cache)
                if canon and looks_like_license_text(canon):
                    return canon, "spdx-canonical-fallback"
        return "", "suspicious-license-text"

    # Dual-license expression: concatenate all matching files
    if license_info["kind"] == "expression" and len(license_info["all_ids"]) > 1:
        parts: list[str] = []
        used_files: set[str] = set()
        for sid in license_info["all_ids"]:
            best = _best_match_for_id(sid, decoded)
            if best and best not in used_files:
                parts.append(f"=== {best} ({sid}) ===\n\n{decoded[best]}")
                used_files.add(best)
        # Append NOTICE files if any weren't already used
        for name, text in decoded.items():
            if "notice" in name.lower() and name not in used_files:
                parts.append(f"=== NOTICE ({name}) ===\n\n{text}")
                used_files.add(name)
        if parts:
            return "\n\n".join(parts), "concatenated-dual"

    # Single license: prefer the file matching the declared SPDX id
    if license_info["kind"] == "id":
        best = _best_match_for_id(license_info["value"], decoded)
        if best:
            body = decoded[best]
            # Append NOTICE if present
            for name, text in decoded.items():
                if "notice" in name.lower() and name != best:
                    body = body + f"\n\n=== NOTICE ({name}) ===\n\n{text}"
            return body, "matched"

    # Fallback: longest file
    longest = max(decoded.items(), key=lambda kv: len(kv[1]))
    body = longest[1]
    for name, text in decoded.items():
        if "notice" in name.lower() and name != longest[0]:
            body = body + f"\n\n=== NOTICE ({name}) ===\n\n{text}"
    return body, "longest-file"


def _best_match_for_id(spdx_id: str, decoded_files: dict[str, str]) -> Optional[str]:
    """Heuristic: file whose name OR content best matches the SPDX id."""
    # Key phrases that identify common SPDX licenses by content
    name_hints = {
        "MIT": ["mit"],
        "Apache-2.0": ["apache", "apache-2", "apache2"],
        "BSD-3-Clause": ["bsd-3", "bsd3", "bsd"],
        "BSD-2-Clause": ["bsd-2", "bsd2", "bsd"],
        "ISC": ["isc"],
        "GPL-3.0-or-later": ["gpl-3", "gpl3", "gplv3"],
        "GPL-3.0": ["gpl-3", "gpl3", "gplv3"],
        "GPL-2.0-or-later": ["gpl-2", "gpl2", "gplv2"],
        "LGPL-2.1": ["lgpl-2", "lgpl2.1", "lgplv2"],
        "LGPL-3.0": ["lgpl-3", "lgpl3"],
        "MPL-2.0": ["mpl", "mozilla"],
        "Unlicense": ["unlicense"],
        "Zlib": ["zlib"],
        "PSF-2.0": ["psf", "python"],
    }
    content_keys = {
        "MIT": "Permission is hereby granted, free of charge",
        "Apache-2.0": "Apache License",
        "BSD-3-Clause": "Redistribution and use in source and binary forms",
        "ISC": "Permission to use, copy, modify",
        "GPL-3.0": "GNU GENERAL PUBLIC LICENSE",
        "GPL-3.0-or-later": "GNU GENERAL PUBLIC LICENSE",
        "GPL-2.0": "GNU GENERAL PUBLIC LICENSE",
        "LGPL-2.1": "GNU LESSER GENERAL PUBLIC LICENSE",
        "MPL-2.0": "Mozilla Public License",
        "PSF-2.0": "PYTHON SOFTWARE FOUNDATION",
    }

    # 1. Filename hint match
    for fname in decoded_files:
        low = fname.lower()
        for hint in name_hints.get(spdx_id, []):
            if hint in low:
                return fname

    # 2. Content phrase match
    target_phrase = content_keys.get(spdx_id, "").lower()
    if target_phrase:
        for fname, text in decoded_files.items():
            if target_phrase in text[:2000].lower():
                return fname

    # 3. No clear match
    return None


def harvest_copyrights(text_blobs: list[str], seed: list[str] | None = None) -> list[str]:
    """Run COPYRIGHT_RE over all blobs, dedupe (case-insensitive), sort."""
    seen: dict[str, str] = {}  # lowercase -> original
    for line in seed or []:
        seen[line.lower().strip()] = line.strip()
    for blob in text_blobs:
        for m in COPYRIGHT_RE.finditer(blob):
            raw = m.group(0).strip()
            # Collapse internal whitespace (incl. embedded newlines that the
            # leading \s+ may have eaten) into single spaces. Don't split-
            # and-take-first; that loses the name when it falls on the line
            # AFTER "Copyright (c)".
            raw = re.sub(r"\s+", " ", raw).strip()
            # Trim trailing punctuation noise
            raw = raw.rstrip(",;: ")
            # Cap absurdly long captures
            if len(raw) > 250:
                raw = raw[:250]
            # Require at least one letter run of 2+ chars after the year —
            # filters out fragments that captured only "Copyright (c) 2020"
            if not re.search(r"[A-Za-z]{2,}", raw[raw.find(" "):]):
                continue
            key = raw.lower()
            if key not in seen:
                seen[key] = raw
    return sorted(seen.values(), key=str.lower)


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def sanitize(s: str) -> str:
    out = s
    for pat in SANITIZE_PATTERNS:
        out = pat.sub("[REDACTED-PATH]", out)
    return out


def sanitize_list(items: list[str]) -> list[str]:
    return [sanitize(x) for x in items]


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def detect_drift(component: dict, license_info: dict, source_text: str) -> Optional[dict]:
    """Quick drift heuristic: declared SPDX vs what the source LICENSE looks
    like. Returns a drift-report entry or None."""
    if not source_text or license_info["kind"] == "none":
        return None
    declared = license_info["value"]
    text_lower = source_text[:3000].lower()

    # Map of "obviously this license" content fingerprints
    fingerprints = {
        "GPL-3.0": "gnu general public license\n                       version 3",
        "GPL-2.0": "gnu general public license\n                       version 2",
        "LGPL-2.1": "gnu lesser general public license\n                       version 2.1",
        "Apache-2.0": "apache license\n                           version 2.0",
        "MIT": "permission is hereby granted, free of charge",
        "BSD-3-Clause": "redistribution and use in source and binary forms",
        "ISC": "permission to use, copy, modify, and/or distribute",
        "MPL-2.0": "mozilla public license version 2.0",
        "PSF-2.0": "python software foundation license",
    }
    detected: list[str] = []
    for sid, fp in fingerprints.items():
        if fp in text_lower:
            detected.append(sid)
    if not detected:
        return None

    # Normalize declared id for comparison (strip "-or-later", etc.)
    def norm(x: str) -> str:
        return x.replace("-or-later", "").replace("-only", "").lower()

    declared_norm = norm(declared)
    declared_ids_norm = [norm(d) for d in license_info["all_ids"]]
    detected_norm = [norm(d) for d in detected]

    # Pass if any declared id matches any detected
    if any(d in detected_norm for d in declared_ids_norm or [declared_norm]):
        return None

    return {
        "purl": component.get("purl", ""),
        "name": component.get("name", ""),
        "version": component.get("version", ""),
        "declared": declared,
        "detected": ", ".join(detected),
        "evidence": source_text[:500],
    }


# ---------------------------------------------------------------------------
# Per-component enrichment
# ---------------------------------------------------------------------------


def enrich_component(
    component: dict, sys_tools_map: dict, cache_dir: Path, no_cache: bool
) -> tuple[dict, dict]:
    """Returns (updated_component, report_entry).

    report_entry keys:
      status: "enriched" | "skipped" | <failure-category>
      reason: human-readable note
      drift: optional drift entry
      source_tag: which body-selection branch fired
    """
    report = {
        "name": component.get("name", ""),
        "version": component.get("version", ""),
        "purl": component.get("purl", ""),
        "category": get_category(component),
        "status": "",
        "reason": "",
        "drift": None,
        "source_tag": "",
    }

    license_info = get_license_info(component)

    # Skip rules
    if license_info["kind"] == "name" and "LicenseRef-" in license_info["value"]:
        report["status"] = "skipped"
        report["reason"] = f"proprietary license '{license_info['value']}'"
        return component, report

    plan = dispatch(component, sys_tools_map)
    if plan.get("kind") == "none":
        # Try SPDX canonical fallback directly
        if license_info["kind"] in ("id", "expression"):
            body, tag = select_license_text({}, license_info, cache_dir, no_cache)
            if body:
                _write_enrichment(component, body, [], license_info)
                report["status"] = "enriched"
                report["source_tag"] = tag
                report["reason"] = f"no source dispatch ({plan.get('reason', '')}); used SPDX canonical"
                return component, report
        report["status"] = "unresolvable-source"
        report["reason"] = plan.get("reason", "no dispatcher matched")
        return component, report

    try:
        license_files, source_headers, copyright_seed = _fetch_artifacts(plan, cache_dir, no_cache)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            report["status"] = "download-404"
        else:
            report["status"] = "download-error"
        report["reason"] = f"HTTP {e.code}: {e.reason}"
        # Try SPDX canonical fallback
        if license_info["kind"] in ("id", "expression"):
            body, tag = select_license_text({}, license_info, cache_dir, no_cache)
            if body:
                _write_enrichment(component, body, [], license_info)
                report["status"] = "enriched"
                report["source_tag"] = tag
                report["reason"] += " — fell back to SPDX canonical"
                return component, report
        return component, report
    except Exception as e:
        report["status"] = "download-error"
        report["reason"] = f"{type(e).__name__}: {e}"
        # SPDX fallback
        if license_info["kind"] in ("id", "expression"):
            body, tag = select_license_text({}, license_info, cache_dir, no_cache)
            if body:
                _write_enrichment(component, body, [], license_info)
                report["status"] = "enriched"
                report["source_tag"] = tag
                report["reason"] += " — fell back to SPDX canonical"
                return component, report
        return component, report

    body, source_tag = select_license_text(license_files, license_info, cache_dir, no_cache)
    if not body:
        report["status"] = "unresolvable-license"
        report["reason"] = source_tag
        return component, report

    body = sanitize(body)

    # Harvest copyrights from license body + source headers + seed
    blobs = [body] + source_headers
    copyrights = harvest_copyrights(blobs, seed=copyright_seed)
    copyrights = sanitize_list(copyrights)

    # Drift detection
    drift = detect_drift(component, license_info, body)
    if drift:
        report["drift"] = drift

    _write_enrichment(component, body, copyrights, license_info)
    report["status"] = "enriched"
    report["source_tag"] = source_tag
    return component, report


def _fetch_artifacts(
    plan: dict, cache_dir: Path, no_cache: bool
) -> tuple[dict[str, bytes], list[str], list[str]]:
    """Return (license_files, source_headers, copyright_seed) per plan kind."""
    kind = plan["kind"]
    if kind == "tarball":
        files = fetch_tarball_license_files(plan["url"], plan.get("path_prefix", ""), cache_dir, no_cache)
        headers = fetch_tarball_source_headers(plan["url"], plan.get("path_prefix", ""), cache_dir, no_cache)
        return files, headers, []
    if kind == "npm-via-metadata":
        files = fetch_npm_via_metadata(plan["metadata_url"], plan.get("path_prefix", ""), cache_dir, no_cache)
        # Skip source headers for NPM — package tarball name varies, complicates extraction
        return files, [], []
    if kind == "pypi-via-metadata":
        try:
            files = fetch_pypi_via_metadata(plan["metadata_url"], cache_dir, no_cache)
            return files, [], []
        except (urllib.error.HTTPError, RuntimeError):
            # Fall back to GitHub homepage if package not on PyPI
            fallback = plan.get("homepage_fallback", "")
            if fallback.startswith("https://github.com/"):
                m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)(?:/tree/([^/?#]+))?", fallback)
                if m:
                    owner, repo, ref = m.group(1), m.group(2), m.group(3) or "main"
                    base = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}"
                    return fetch_single_file_probes(base, cache_dir, no_cache), [], []
            raise
    if kind == "hf-probe":
        return fetch_single_file_probes(plan["base_url"], cache_dir, no_cache), [], []
    if kind == "gh-raw-probe":
        return fetch_single_file_probes(plan["base_url"], cache_dir, no_cache), [], []
    if kind == "system-curated":
        # Download tarball, extract listed license files + notice files
        blob = cached_fetch(plan["url"], cache_dir, no_cache)
        files: dict[str, bytes] = {}
        prefix = plan.get("path_prefix", "")
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                # Collect license files in the order declared
                for lic_name in plan["license_files"] + plan.get("notice_files", []):
                    candidate = prefix + lic_name if prefix else lic_name
                    try:
                        member = tf.getmember(candidate)
                    except KeyError:
                        continue
                    f = tf.extractfile(member)
                    if f is not None:
                        files[lic_name] = f.read()
        except tarfile.TarError as e:
            raise RuntimeError(f"system-tool tarball error: {e}") from e

        # For system-curated, build an ordered concatenated body now
        # rather than relying on select_license_text's heuristics
        # (curation map declares exact order).
        ordered_text_parts: list[str] = []
        for lic_name in plan["license_files"]:
            if lic_name in files:
                text = files[lic_name].decode("utf-8", errors="replace")
                ordered_text_parts.append(f"=== {lic_name} ({plan.get('primary_license_id', '')}) ===\n\n{text}")
        for notice_name in plan.get("notice_files", []):
            if notice_name in files:
                text = files[notice_name].decode("utf-8", errors="replace")
                ordered_text_parts.append(f"=== NOTICE ({notice_name}) ===\n\n{text}")
        if ordered_text_parts:
            concat = "\n\n".join(ordered_text_parts)
            # Encode as a single synthetic LICENSE entry so select_license_text picks it
            return ({"_SYSTEM_CURATED_BODY_": concat.encode("utf-8")},
                    [],
                    plan.get("copyright_seed", []))
        return {}, [], plan.get("copyright_seed", [])
    return {}, [], []


def _write_enrichment(component: dict, license_text: str, copyrights: list[str], license_info: dict) -> None:
    """Mutate component in place: add license.text + component.copyright."""
    encoded = base64.b64encode(license_text.encode("utf-8")).decode("ascii")

    if license_info["kind"] == "expression":
        # No natural CycloneDX home for expression text. Put it in a property
        # AND set component.copyright. Flag in report.
        props = component.setdefault("properties", [])
        # Replace any existing com.raidio.licenseText
        props[:] = [p for p in props if p.get("name") != "com.raidio.licenseText"]
        props.append({
            "name": "com.raidio.licenseText",
            "value": encoded,
        })
    else:
        for lic in component.get("licenses", []):
            inner = lic.get("license")
            if inner is not None:
                inner["text"] = {
                    "contentType": "text/plain",
                    "encoding": "base64",
                    "content": encoded,
                }
                break  # Only attach to the first license entry

    if copyrights:
        component["copyright"] = "\n".join(copyrights)


# ---------------------------------------------------------------------------
# NOTICES.txt rendering
# ---------------------------------------------------------------------------


NOTICES_HEADER = (
    "rAIdio.bot — Third-Party Notices\n"
    "Plain-text rendering derived from sbom.json (CycloneDX 1.5).\n"
    "Per-component verbatim license texts + copyright statements.\n"
    "Generated by tools/sbom_enrich.py at release time.\n"
    "\n"
    "═══════════════════════════════════════════════════════════════════════════\n"
)


def render_notices(sbom: dict) -> str:
    parts: list[str] = [NOTICES_HEADER]
    for c in sbom.get("components", []):
        name = c.get("name", "?")
        version = c.get("version", "?")
        purl = c.get("purl", "")
        homepage = get_homepage(c)
        license_info = get_license_info(c)
        license_label = license_info["value"] or "Unknown"

        # Decode license text
        text = ""
        for lic in c.get("licenses", []):
            inner = lic.get("license", {})
            tobj = inner.get("text")
            if tobj and tobj.get("encoding") == "base64":
                try:
                    text = base64.b64decode(tobj["content"]).decode("utf-8", errors="replace")
                    break
                except Exception:
                    pass
        if not text:
            # Expression case: read from property
            for p in c.get("properties", []):
                if p.get("name") == "com.raidio.licenseText":
                    try:
                        text = base64.b64decode(p["value"]).decode("utf-8", errors="replace")
                        break
                    except Exception:
                        pass

        copyright_text = c.get("copyright", "")

        block = (
            f"COMPONENT:    {name} {version}\n"
            f"LICENSE:      {license_label}\n"
            f"HOMEPAGE:     {homepage}\n"
            f"PURL:         {purl}\n"
            f"\n"
            f"COPYRIGHT\n"
            f"─────────\n"
            f"{copyright_text or '(none recorded)'}\n"
            f"\n"
            f"LICENSE TEXT\n"
            f"────────────\n"
            f"{text or '(license text not embedded; see homepage)'}\n"
            f"\n"
            f"═══════════════════════════════════════════════════════════════════════════\n"
        )
        parts.append(block)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _script_git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def update_metadata_tools(sbom: dict) -> None:
    """Replace metadata.tools with the memescreamer/sbom-enrich entry.
    No hostname, no OS, no username — just the script's git SHA."""
    sbom.setdefault("metadata", {})["tools"] = [
        {
            "vendor": "memescreamer",
            "name": "sbom-enrich",
            "version": _script_git_sha(),
        }
    ]


def verify_sample(sbom: dict, count: int = 5) -> None:
    """Sample-decode N license texts; abort if any look broken."""
    enriched = []
    for c in sbom.get("components", []):
        for lic in c.get("licenses", []):
            inner = lic.get("license", {})
            tobj = inner.get("text")
            if tobj and tobj.get("encoding") == "base64":
                enriched.append((c.get("name"), tobj["content"]))
                break
    if not enriched:
        print("[verify] WARNING: no enriched components found to sample.", file=sys.stderr)
        return
    random.seed(0x1A1D01)  # deterministic so re-runs check the same set
    samples = random.sample(enriched, min(count, len(enriched)))
    for name, content in samples:
        try:
            text = base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception as e:
            raise SystemExit(f"[verify] {name}: base64 decode failed: {e}")
        if not looks_like_license_text(text):
            raise SystemExit(
                f"[verify] {name}: sample text fails sanity check\n"
                f"first 200 chars:\n{text[:200]}"
            )
        print(f"[verify] {name}: OK ({len(text)} bytes)", file=sys.stderr)


def write_report(report_path: Path, results: list[dict], skip_summary: dict) -> None:
    lines = ["rAIdio.bot SBOM enrichment — processing report\n", "=" * 64, ""]
    by_status: dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    lines.append("Counts by status:")
    for k, v in sorted(by_status.items()):
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Skip math:")
    for k, v in skip_summary.items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Per-component (non-success rows only):")
    lines.append("-" * 64)
    for r in results:
        if r["status"] not in ("enriched", "skipped"):
            lines.append(
                f"  [{r['status']}] {r['name']} {r['version']} ({r['category']}): {r['reason']}"
            )
    lines.append("")
    lines.append("Source-tag distribution (enriched components):")
    tags: dict[str, int] = {}
    for r in results:
        if r["status"] == "enriched":
            tags[r["source_tag"]] = tags.get(r["source_tag"], 0) + 1
    for k, v in sorted(tags.items()):
        lines.append(f"  {k}: {v}")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_drift_report(drift_path: Path, results: list[dict]) -> None:
    drift_entries = [r["drift"] for r in results if r.get("drift")]
    if not drift_entries:
        drift_path.write_text("# Drift report — no entries.\n# Next push is unblocked.\n", encoding="utf-8")
        return
    lines = [
        "rAIdio.bot SBOM enrichment — license drift report",
        "=" * 64,
        f"Total drift entries: {len(drift_entries)}",
        "",
        "Each entry below has a declared SPDX license in the SBOM that does NOT",
        "match what the source LICENSE file actually says. Each must be audited:",
        "  - If the declared license is the right call (a deliberate hand-",
        "    curation override, or a more permissive choice from a dual-license",
        "    expression), mark it in the curation log and remove from this file.",
        "  - If the upstream license changed and our SBOM didn't catch up, update",
        "    tools/generate_sbom.py and re-run.",
        "",
        "While this file is non-empty, steam/push.ps1 refuses to push.",
        "=" * 64,
        "",
    ]
    for e in drift_entries:
        lines.append(f"  {e['name']} {e['version']}")
        lines.append(f"    purl:     {e['purl']}")
        lines.append(f"    declared: {e['declared']}")
        lines.append(f"    detected: {e['detected']}")
        lines.append(f"    evidence (first 500 chars):")
        for ln in e["evidence"].splitlines()[:10]:
            lines.append(f"      | {ln}")
        lines.append("")
    drift_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, help="Path to input CycloneDX 1.5 JSON")
    parser.add_argument("--output", required=True, help="Path to output enriched sbom.json (sbom-repo root)")
    parser.add_argument(
        "--cache-dir",
        default=str(DEFAULT_CACHE_DIR),
        help=f"Cache directory (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument("--no-cache", action="store_true", help="Force fresh downloads")
    parser.add_argument(
        "--system-tools-map",
        default=str(SYSTEM_TOOLS_MAP_PATH),
        help="Path to System Tools curation JSON",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only the first N components (for testing). 0 = all.",
    )
    args = parser.parse_args()

    sbom_in_path = Path(args.sbom)
    sbom_out_path = Path(args.output)
    cache_dir = Path(args.cache_dir)
    sys_tools_map_path = Path(args.system_tools_map)

    sbom = json.loads(sbom_in_path.read_text(encoding="utf-8"))
    sys_tools_map = json.loads(sys_tools_map_path.read_text(encoding="utf-8"))
    # Drop the comment key if present
    sys_tools_map.pop("_comment", None)

    components = sbom.get("components", [])
    total = len(components)
    if args.limit > 0:
        components = components[: args.limit]
    print(f"[enrich] Loaded {total} components; processing {len(components)}", file=sys.stderr)

    results: list[dict] = []
    skip_summary = {
        "total_in_sbom": total,
        "processed": 0,
        "skipped": 0,
        "enriched": 0,
        "failed": 0,
    }

    for idx, c in enumerate(components):
        print(f"[enrich] [{idx+1}/{len(components)}] {c.get('name', '?')} {c.get('version', '?')}", file=sys.stderr)
        updated, report = enrich_component(c, sys_tools_map, cache_dir, args.no_cache)
        results.append(report)
        skip_summary["processed"] += 1
        if report["status"] == "enriched":
            skip_summary["enriched"] += 1
        elif report["status"] == "skipped":
            skip_summary["skipped"] += 1
        else:
            skip_summary["failed"] += 1

    # Update metadata.tools to the memescreamer/sbom-enrich entry
    update_metadata_tools(sbom)

    # Sanitize the whole SBOM body defensively (catches anything that
    # slipped past per-component sanitize)
    def _walk(obj):
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(x) for x in obj]
        if isinstance(obj, str):
            return sanitize(obj)
        return obj

    sbom = _walk(sbom)

    # Verify before write
    verify_sample(sbom)

    # Atomic write
    sbom_out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = sbom_out_path.with_suffix(".tmp")
    tmp_out.write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp_out.replace(sbom_out_path)
    print(f"[enrich] Wrote {sbom_out_path}", file=sys.stderr)

    # NOTICES.txt
    notices_path = sbom_out_path.parent / "NOTICES.txt"
    notices_path.write_text(render_notices(sbom), encoding="utf-8")
    print(f"[enrich] Wrote {notices_path}", file=sys.stderr)

    # Reports
    report_path = sbom_out_path.parent / "enrich-report.txt"
    drift_path = sbom_out_path.parent / "drift-report.txt"
    write_report(report_path, results, skip_summary)
    write_drift_report(drift_path, results)
    print(f"[enrich] Wrote {report_path}", file=sys.stderr)
    print(f"[enrich] Wrote {drift_path}", file=sys.stderr)

    # Summary
    print(
        f"[enrich] Done. enriched={skip_summary['enriched']} "
        f"skipped={skip_summary['skipped']} failed={skip_summary['failed']} "
        f"(total {skip_summary['total_in_sbom']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
