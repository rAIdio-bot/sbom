#!/usr/bin/env python3
"""
sbom_enrich.py — enrich a CycloneDX 1.5 SBOM with verbatim license texts
and copyright notices harvested from source artifacts.

Produces three artifacts at the sbom repo root:
  - sbom.<platform>.json           canonical enriched SBOM (CycloneDX 1.5)
  - NOTICES.<platform>.txt         plain-text rendering derived from sbom.<platform>.json
  - enrich-report.<platform>.txt   processing summary (counts, per-component failures)
  - drift-report.<platform>.txt    license-mismatch queue (drives push.ps1 gate)

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

# Narrower NOTICE-only matcher used to tag bundled-attribution entries
# at curated-system extraction time (audit_license_compliance.py uses
# the same pattern; kept here so both modules share one source of truth).
NOTICE_FILE_RE = re.compile(r"(?i)(?:^|/)NOTICE([._-]\S*)?$")

# Copyright extraction — handles ©, (c), (C), word "Copyright", year ranges,
# year-only headers ("2020,2021,2022 Author") and trailing email.
# DOTALL not set, so `.` doesn't span lines; the year and name must be on
# the same logical line after whitespace-collapse.
COPYRIGHT_RE = re.compile(
    r"(?:Copyright\s*(?:\([cC]\)|©)?|©|\([cC]\))"
    r"\s+\d{4}(?:[\s,\-]+\d{2,4})*"
    r"\s+[A-Za-z][^\r\n]{2,200}"
)

# SPDX-License-Identifier markers in source-file headers. Captures the
# right-hand side which may be a bare id (`MIT`), a WITH-exception
# (`Apache-2.0 WITH LLVM-exception`), or an SPDX expression
# (`Apache-2.0 OR MIT`). Stops at end-of-line / `*/` / similar comment
# trailers. Only meaningful in the first ~50 lines of a file — test
# fixtures and docstrings deeper in the body produce false positives.
SPDX_HEADER_RE = re.compile(
    r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+()]+(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.\-+()]+)*)"
)

# Source-file extensions worth scanning for SPDX headers + copyrights.
# Mirrors the set in fetch_tarball_source_headers (kept in sync).
_SOURCE_EXT_RE = re.compile(
    r"\.(rs|py|js|ts|svelte|c|cc|cpp|h|hpp|go|java|rb|php|sh|cs|swift|kt|m|mm|toml|cmake)$",
    re.IGNORECASE,
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
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=ctx) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- dev/release tool, fixed deps.dev/PyPI host, not shipped
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


def cached_only_fetch(url: str, cache_dir: Path) -> Optional[bytes]:
    """Return cached bytes for url, or None if not cached. Never makes a
    network request. Used by the in-pipeline evidence pass so push time
    doesn't grow with cold-cache components — coverage gradually fills
    in as the offline deep scan populates the cache."""
    key = _cache_key((url,))
    cache_path = cache_dir / key
    if cache_path.exists():
        return cache_path.read_bytes()
    return None


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


def get_upstream_source_url(component: dict) -> str:
    """Return the canonical upstream source URL (CycloneDX externalReference
    type 'vcs'), or empty string. Populated by generate_cyclonedx.py from
    the `upstream_source_url` field on AI_MODELS / PYTHON_DEPS / SYSTEM_TOOLS
    entries. Used as a LICENSE-fetch fallback when the component's primary
    distribution surface (HF mirror, wheel, etc.) carries no LICENSE file.
    Added 2026-05-22 per Till Jaeger Q1+Q3 follow-ups.
    """
    for r in component.get("externalReferences", []):
        if r.get("type") == "vcs":
            return r.get("url", "")
    return ""


def get_embedded_in_component(component: dict) -> str:
    """Return the SBOM component reference (name@version) inside which this
    component's source code ships as a vendored sub-tree, or empty string.
    Populated by generate_cyclonedx.py from `embedded_in_component` field.
    Example: BigVGAN sources ship inside SeedVC-ComfyUI@0f6481215b64.
    Added 2026-05-22 per Till Jaeger Q1 follow-up.
    """
    for p in component.get("properties", []):
        if p.get("name") == "com.raidio.embedded-in":
            return p.get("value", "")
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


def resolve_python_package(name: str, version: str, homepage: str, upstream_source_url: str = "") -> dict:
    """Resolve a Python package to the right fetch plan.

    PEP 440 LOCAL VERSION SEGMENT HANDLING (Till Jaeger Q3, 2026-05-22):
    Versions matching `\\+(cu|cpu|rocm)\\w+` are CUDA/CPU/ROCm-specific
    wheels published by PyTorch at `download.pytorch.org/whl/<flavor>/`,
    NOT on PyPI. Probing PyPI for them returns 404, which previously
    caused us to fall through to a github-raw single-LICENSE probe and
    miss every per-file copyright in the source tree. For the
    torch-family entries we now prefer the GitHub release-tag source
    tarball, which contains the full source tree with every vendored
    sub-tree's copyright header in place (giflib, deformable-conv,
    etc.). We strip the local-version segment from `version` to derive
    the upstream tag (e.g. 0.25.0+cu128 -> 0.25.0 -> v0.25.0).

    For ordinary Python packages without a `+local` segment, the
    existing PyPI sdist/wheel path is unchanged.
    """
    # Strip PEP 440 local-version segment ("+cu128", "+cpu", "+rocm6.0" etc.)
    local_segment_match = re.match(r"^([^+]+)(\+\S+)$", version)
    if local_segment_match:
        # Choose the upstream URL: explicit upstream_source_url wins,
        # otherwise fall back to homepage if it's a github URL. The torch
        # family entries are mostly in the auto-extracted JSON without
        # upstream_source_url set; the homepage already points at the right
        # github repo (https://github.com/pytorch/vision etc.).
        upstream = upstream_source_url
        if not upstream and homepage.startswith("https://github.com/"):
            upstream = homepage
        base_version = local_segment_match.group(1)
        m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)", upstream) if upstream else None
        if m:
            owner, repo = m.group(1), m.group(2)
            # Try the conventional release-tag tarball first.
            return {
                "kind": "github-release-tarball",
                "owner": owner,
                "repo": repo,
                "tag_candidates": [f"v{base_version}", base_version, f"release/{base_version}"],
                "base_version": base_version,
                "upstream_source_url": upstream,
                "homepage_fallback": homepage,
            }
    plan = {
        "kind": "pypi-via-metadata",
        "format": "auto",  # sdist preferred, wheel fallback
        "metadata_url": f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json",
        "homepage_fallback": homepage,
    }
    if upstream_source_url:
        plan["upstream_source_url"] = upstream_source_url
    return plan


def resolve_hf_model(component: dict) -> dict:
    homepage = get_homepage(component)
    m = re.match(r"https?://huggingface\.co/([^/]+)/([^/?#]+)", homepage)
    if not m:
        # Not HF — but this category was supposed to be HF. Fall through to
        # whatever resolver kind is appropriate. We accept github.com here too
        # because some AI Models point directly at GitHub (e.g. RMVPE).
        if homepage.startswith("https://github.com/"):
            return resolve_github_raw(component)
        return {"kind": "none", "reason": f"HF URL not parseable: {homepage}"}
    owner, repo = m.group(1), m.group(2)
    revision = component.get("version", "main")
    plan = {
        "kind": "hf-probe",
        "owner": owner,
        "repo": repo,
        "revision": revision,
        "base_url": f"https://huggingface.co/{owner}/{repo}/resolve/{revision}",
    }
    # Carry the canonical upstream URL as a fallback (Till Jaeger Q1, 2026-05-22).
    # HF model mirrors typically contain ONLY weight files + config — no LICENSE.
    # When the hf-probe finds no license-named files, the upstream GitHub
    # repository (where the code + LICENSE actually live) is probed instead so
    # the NVIDIA / Plachta / OpenAI / Meta / etc. copyright lines are harvested.
    upstream = get_upstream_source_url(component)
    if upstream:
        plan["upstream_source_url"] = upstream
    return plan


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
        return resolve_python_package(name, version, get_homepage(component), get_upstream_source_url(component))
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
    url: str, path_prefix: str, cache_dir: Path, no_cache: bool, fmt: str = "tar.gz", max_files: int = 300, max_lines: int = 50
) -> list[str]:
    """Read top-N lines of up to M source-looking files in the tarball.
    Returns a list of concatenated header blobs for copyright harvesting.

    Extension set and sample cap kept in sync with audit_license_compliance.py's
    extract_source_header_copyrights() — otherwise the audit finds vendored
    copyrights (e.g. zlib's Mark Adler attribution inside grpcio) that the
    enricher missed, producing false-positive violations.
    """
    blob = cached_fetch(url, cache_dir, no_cache)
    source_exts = re.compile(
        r"\.(rs|py|js|ts|svelte|c|cc|cpp|h|hpp|go|java|rb|php|sh|cs|swift|kt|m|mm|toml|cmake|S|asm)$",
        re.IGNORECASE,
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


def scan_cached_tarball_for_spdx(
    url: str,
    path_prefix: str,
    cache_dir: Path,
    fmt: str = "tar.gz",
    head_lines: int = 50,
    max_files: int = 2000,
) -> list[dict]:
    """Walk a tarball that's already in the cache and pull SPDX-License-Identifier
    markers out of the first head_lines lines of every source file. Returns a
    list of {"path": str, "spdx": [str, ...], "line": int} dicts (one per file
    that contained at least one SPDX marker).

    Cache-only by design: returns [] on cache miss without making a network
    call. The in-pipeline evidence pass uses this so push time doesn't grow
    with cold-cache components.

    head_lines bound is intentional — SPDX markers are convention-bound to
    the file header. Test fixtures and docstrings deeper in the body are
    the principal source of false positives, so we don't read past 50.
    max_files cap is generous (2000) to cover crates with hundreds of small
    .rs files but still bound the worst case.
    """
    blob = cached_only_fetch(url, cache_dir)
    if blob is None:
        return []
    findings: list[dict] = []

    def _scan_one(rel_path: str, content: bytes) -> None:
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return
        spdx_ids: list[str] = []
        first_line = 0
        for i, line in enumerate(text.splitlines()[:head_lines], start=1):
            for m in SPDX_HEADER_RE.finditer(line):
                ident = m.group(1).strip()
                if ident and ident not in spdx_ids:
                    spdx_ids.append(ident)
                    if first_line == 0:
                        first_line = i
        if spdx_ids:
            findings.append({"path": rel_path, "spdx": spdx_ids, "line": first_line})

    try:
        if fmt == "zip" or url.endswith(".zip") or url.endswith(".whl"):
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                infos = [
                    i
                    for i in zf.infolist()
                    if not i.is_dir() and _SOURCE_EXT_RE.search(i.filename)
                ]
                for info in infos[:max_files]:
                    rel = info.filename
                    if path_prefix and rel.startswith(path_prefix):
                        rel = rel[len(path_prefix) :]
                    try:
                        _scan_one(rel, zf.read(info.filename))
                    except Exception:
                        continue
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                infos = [m for m in tf.getmembers() if m.isfile() and _SOURCE_EXT_RE.search(m.name)]
                for member in infos[:max_files]:
                    rel = member.name
                    if path_prefix and rel.startswith(path_prefix):
                        rel = rel[len(path_prefix) :]
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    try:
                        _scan_one(rel, f.read())
                    except Exception:
                        continue
    except (tarfile.TarError, zipfile.BadZipFile):
        return []

    # Deterministic order — matters for byte-identical re-runs of sbom.<platform>.json.
    findings.sort(key=lambda d: d["path"])
    return findings


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


def fetch_npm_source_headers(metadata_url: str, cache_dir: Path, no_cache: bool) -> list[str]:
    """Read source-file headers from the npm package tarball for copyright
    harvesting. npm tarballs unpack under `package/`. Captures copyrights that
    live only in source headers (e.g. 'Tauri Programme'), not in the LICENSE
    body, so the audit's source-header copyright check is satisfied. (Till
    Jaeger review.)"""
    try:
        meta = json.loads(cached_fetch(metadata_url, cache_dir, no_cache))
        tarball_url = meta.get("dist", {}).get("tarball")
        if not tarball_url:
            return []
        return fetch_tarball_source_headers(tarball_url, "package/", cache_dir, no_cache)
    except Exception:
        return []


def _resolve_pypi_artifact(metadata_url: str, cache_dir: Path, no_cache: bool) -> tuple[str, str]:
    """Return (target_url, fmt) for the preferred PyPI artifact (sdist over wheel)."""
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
    fmt = "zip" if target_url.endswith(".whl") else "tar.gz"
    return target_url, fmt


def fetch_pypi_via_metadata(metadata_url: str, cache_dir: Path, no_cache: bool) -> dict[str, bytes]:
    target_url, fmt = _resolve_pypi_artifact(metadata_url, cache_dir, no_cache)
    # PyPI sdists unpack to <name>-<version>/; wheels unpack flat. Don't pre-strip.
    return fetch_tarball_license_files(target_url, "", cache_dir, no_cache, fmt=fmt)


def fetch_pypi_source_headers(metadata_url: str, cache_dir: Path, no_cache: bool) -> list[str]:
    """Read source-file headers from the PyPI sdist/wheel for copyright harvesting."""
    target_url, fmt = _resolve_pypi_artifact(metadata_url, cache_dir, no_cache)
    return fetch_tarball_source_headers(target_url, "", cache_dir, no_cache, fmt=fmt)


# ---------------------------------------------------------------------------
# License text + copyright harvest
# ---------------------------------------------------------------------------


SPDX_CANONICAL_CACHE: dict[str, str] = {}


def fetch_spdx_canonical(spdx_id: str, cache_dir: Path, no_cache: bool) -> Optional[str]:
    """Fetch the canonical text for an SPDX license id from spdx.org. Returns
    None on 404 (id not in SPDX database). Tries .txt first, then .json
    (some licenses such as PSF-2.0 only have the .json endpoint published)."""
    if spdx_id in SPDX_CANONICAL_CACHE:
        return SPDX_CANONICAL_CACHE[spdx_id]
    # WITH exceptions: strip the exception, fetch the base license
    base_id = spdx_id.split(" WITH ")[0].strip()
    # Try plain text first
    try:
        url = f"https://spdx.org/licenses/{base_id}.txt"
        content = cached_fetch(url, cache_dir, no_cache).decode("utf-8", errors="replace")
        SPDX_CANONICAL_CACHE[spdx_id] = content
        return content
    except urllib.error.HTTPError:
        pass
    except urllib.error.URLError:
        return None
    # Fall back to JSON (PSF-2.0 etc. ship only .json)
    try:
        url = f"https://spdx.org/licenses/{base_id}.json"
        raw = cached_fetch(url, cache_dir, no_cache).decode("utf-8", errors="replace")
        content = json.loads(raw).get("licenseText", "")
        if content:
            SPDX_CANONICAL_CACHE[spdx_id] = content
            return content
    except urllib.error.HTTPError:
        return None
    except urllib.error.URLError:
        return None
    except (ValueError, KeyError):
        return None
    return None


def looks_like_license_text(text: str) -> bool:
    """Reject obvious garbage / HTML 404 pages."""
    if not text or len(text) < 200:
        return False
    head = text[:500].lower()
    if "<html" in head or "<!doctype" in head:
        return False
    # Scan a wide window — PSF/Python LICENSE files prepend a multi-page
    # history section before the legal terms begin (the word "license" first
    # appears around char 2100, "warranty" around 4800). Anything that's a
    # real license-bearing file will have at least one of these keywords
    # within the first ~6000 chars.
    body = text[:6000].lower()
    if not any(kw in body for kw in (
        "permission", "license", "copyright", "redistribut",
        "warranty", "python software foundation", "psf"
    )):
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

    # Decode every license-like file, then split into:
    #   notices: NOTICE / NOTICES / NOTICE.txt etc — required to be
    #            preserved verbatim by Apache-2.0 §4(d) and the BSD
    #            attribution clauses, and often legitimately short
    #            (50-300 bytes of attribution-only text). MUST NOT be
    #            filtered by looks_like_license_text's 200-byte floor.
    #   license_bodies: everything else — the actual LICENSE bodies, where
    #                   we apply the size/HTML-404 filter to drop garbage.
    decoded: dict[str, str] = {}
    for name, blob in license_files.items():
        try:
            decoded[name] = blob.decode("utf-8", errors="replace")
        except Exception:
            continue
    notices = {n: t for n, t in decoded.items() if "notice" in n.lower()}
    license_bodies = {
        n: t for n, t in decoded.items()
        if "notice" not in n.lower() and looks_like_license_text(t)
    }
    # Extra LICENSE-named files that aren't the primary picked body —
    # things like LICENSE-THIRD-PARTY (crossbeam-channel), LICENSE-BoringSSL
    # (ring), bundled COPYING files (CPython's Modules/expat/COPYING), or
    # Doc/license.rst (CPython). These carry bundled-component
    # attributions that disappear if we only keep the primary LICENSE.
    # Same key rule as license_bodies; primary-pick logic below excludes
    # whichever entry it actually chose, so the rest get appended.
    aux_bodies = {
        n: t for n, t in decoded.items()
        if "notice" not in n.lower() and looks_like_license_text(t)
    }

    def _append_appendix(body: str, used: set[str]) -> str:
        # Append every NOTICE file (Apache-2.0 §4(d) verbatim preservation)
        # and every non-primary LICENSE-like file (bundled-component
        # attribution preservation per BSD/Apache copyright clauses).
        # used = files already inlined in body so we don't duplicate them.
        for name, text in notices.items():
            if name in used:
                continue
            body = body + f"\n\n=== NOTICE ({name}) ===\n\n{text}"
            used.add(name)
        for name, text in aux_bodies.items():
            if name in used:
                continue
            body = body + f"\n\n=== ATTRIBUTION ({name}) ===\n\n{text}"
            used.add(name)
        return body

    if not license_bodies:
        # No license body passed the filter — try SPDX canonical, then
        # still append NOTICE files if any exist (they carry attribution
        # that the SPDX canonical text does not).
        body = ""
        tag = "suspicious-license-text"
        if license_info["kind"] in ("id", "expression"):
            for sid in (license_info["all_ids"] or [license_info["value"]]):
                canon = fetch_spdx_canonical(sid, cache_dir, no_cache)
                if canon and looks_like_license_text(canon):
                    body = canon
                    tag = "spdx-canonical-fallback"
                    break
        if body or notices:
            return _append_appendix(body, used=set()), tag if body else "notice-only"
        return "", "suspicious-license-text"

    # Dual-license expression: concatenate all matching files
    if license_info["kind"] == "expression" and len(license_info["all_ids"]) > 1:
        parts: list[str] = []
        used_files: set[str] = set()
        for sid in license_info["all_ids"]:
            best = _best_match_for_id(sid, license_bodies)
            if best and best not in used_files:
                parts.append(f"=== {best} ({sid}) ===\n\n{license_bodies[best]}")
                used_files.add(best)
        if parts:
            body = "\n\n".join(parts)
            body = _append_appendix(body, used_files)
            return body, "concatenated-dual"

    # Single license: prefer the file matching the declared SPDX id
    if license_info["kind"] == "id":
        best = _best_match_for_id(license_info["value"], license_bodies)
        if best:
            body = license_bodies[best]
            body = _append_appendix(body, used={best})
            return body, "matched"

    # Fallback: longest license body
    longest_name, longest_text = max(license_bodies.items(), key=lambda kv: len(kv[1]))
    body = _append_appendix(longest_text, used={longest_name})
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


def _is_license_text_copyright(line: str) -> bool:
    """True for copyright lines belonging to the LICENSE DOCUMENT itself
    (license-steward boilerplate or unfilled templates), not the licensed
    component. These already render verbatim in the LICENSE TEXT section, so
    echoing them in the COPYRIGHT block is noise. (Till Jaeger SBOM review.)"""
    low = line.lower()
    # FSF holds copyright on the GNU license TEXTS; no component we ship is
    # itself copyright-FSF, so an FSF line harvested from a license body is the
    # license document's own notice, not the component's.
    if "free software foundation" in low:
        return True
    if any(
        ph in low
        for ph in (
            "<year>",
            "<copyright holders>",
            "<name of author>",
            "<owner>",
            "<organization>",
        )
    ):
        return True
    return False


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


# Optional curation log of known-deliberate license overrides. Loaded
# lazily so the script still works when the file is absent. Entries
# in here suppress drift detection — the SBOM declares X by design
# (e.g., GPL inheritance from a dependency, hand-curated correction
# of a misleading upstream declaration) and we don't want the report
# re-flagging it on every release.
_DRIFT_CURATION_PATH = REPO_ROOT / "tools" / "sbom_drift_curation.json"
_DRIFT_CURATION_CACHE: Optional[dict] = None


def _load_drift_curation() -> dict:
    global _DRIFT_CURATION_CACHE
    if _DRIFT_CURATION_CACHE is not None:
        return _DRIFT_CURATION_CACHE
    if _DRIFT_CURATION_PATH.exists():
        try:
            data = json.loads(_DRIFT_CURATION_PATH.read_text(encoding="utf-8"))
            data.pop("_comment", None)
            _DRIFT_CURATION_CACHE = data
        except Exception:
            _DRIFT_CURATION_CACHE = {}
    else:
        _DRIFT_CURATION_CACHE = {}
    return _DRIFT_CURATION_CACHE


# Curated license texts for vendored sub-components we redistribute (linked /
# compiled into a shipped wheel) but whose own LICENSE file ships in neither the
# wheel nor the sdist — e.g. libffi inside cffi's Windows wheel. (Till Jaeger
# review.) Loaded lazily; absent file = no supplements.
_BUNDLED_LICENSES_PATH = REPO_ROOT / "tools" / "sbom_bundled_licenses.json"
_BUNDLED_LICENSES_CACHE: Optional[dict] = None


def _load_bundled_licenses() -> dict:
    global _BUNDLED_LICENSES_CACHE
    if _BUNDLED_LICENSES_CACHE is not None:
        return _BUNDLED_LICENSES_CACHE
    if _BUNDLED_LICENSES_PATH.exists():
        try:
            data = json.loads(_BUNDLED_LICENSES_PATH.read_text(encoding="utf-8"))
            data.pop("_comment", None)
            _BUNDLED_LICENSES_CACHE = data
        except Exception:
            _BUNDLED_LICENSES_CACHE = {}
    else:
        _BUNDLED_LICENSES_CACHE = {}
    return _BUNDLED_LICENSES_CACHE


def _append_bundled_licenses(
    component: dict, body: str, cache_dir: Path, no_cache: bool
) -> str:
    """Append curated license texts for vendored sub-components we redistribute
    but whose LICENSE file is absent from the fetched wheel/sdist. Keyed by
    name@version; each entry lists {label, url}. Appended as an ATTRIBUTION
    block AFTER primary selection so it can't change which license is picked as
    the component's own. (Till Jaeger review — cffi/libffi.)"""
    key = f"{component['name']}@{component['version']}"
    entry = _load_bundled_licenses().get(key)
    if not entry:
        return body
    for sub in entry.get("extra_license_files", []):
        url = sub.get("url", "")
        label = sub.get("label", url)
        marker = f"=== ATTRIBUTION ({label}) ==="
        if marker in body:
            continue
        try:
            text = cached_fetch(url, cache_dir, no_cache).decode("utf-8", errors="replace")
        except Exception as e:
            print(f"[enrich] bundled-license fetch failed for {key} ({label}): {e}")
            continue
        body = body + f"\n\n{marker}\n\n{sanitize(text)}"
    return body


def _resolve_cached_tarball(plan: dict, cache_dir: Path) -> Optional[tuple[str, str, str]]:
    """Resolve a dispatcher plan to (tarball_url, fmt, path_prefix) IF the
    artifact is already cached. Returns None on cache miss or for plan
    kinds that don't have a single source tarball (HF, GitHub-raw probes).

    Cache-only by design — metadata reads use cached_only_fetch and bail
    on miss rather than triggering downloads."""
    kind = plan.get("kind")
    if kind == "tarball":
        return plan["url"], plan.get("format", "tar.gz"), plan.get("path_prefix", "")
    if kind == "system-curated":
        return plan["url"], "tar.gz", plan.get("path_prefix", "")
    if kind == "npm-via-metadata":
        meta_blob = cached_only_fetch(plan["metadata_url"], cache_dir)
        if meta_blob is None:
            return None
        try:
            meta = json.loads(meta_blob)
            tarball_url = meta.get("dist", {}).get("tarball")
        except Exception:
            return None
        if not tarball_url:
            return None
        return tarball_url, "tar.gz", plan.get("path_prefix", "")
    if kind == "pypi-via-metadata":
        meta_blob = cached_only_fetch(plan["metadata_url"], cache_dir)
        if meta_blob is None:
            return None
        try:
            meta = json.loads(meta_blob)
            urls = meta.get("urls", []) or meta.get("releases", {}).get(
                meta.get("info", {}).get("version", ""), []
            )
        except Exception:
            return None
        sdist_url = wheel_url = None
        for entry in urls:
            if entry.get("packagetype") == "sdist":
                sdist_url = entry.get("url")
            elif entry.get("packagetype") == "bdist_wheel" and wheel_url is None:
                wheel_url = entry.get("url")
        target_url = sdist_url or wheel_url
        if not target_url:
            return None
        fmt = "zip" if target_url.endswith(".whl") else "tar.gz"
        # PyPI sdist unpacks to <name>-<version>/; wheel unpacks flat.
        # path_prefix isn't tracked explicitly so we let the scanner walk
        # the whole tree (LICENSE matcher already handles depth).
        return target_url, fmt, ""
    # HF probes, GitHub-raw probes — no source tarball in cache for Part A.
    return None


def detect_source_header_drift(
    component: dict,
    license_info: dict,
    file_evidence: list[dict],
) -> Optional[dict]:
    """Compare aggregated SPDX IDs from source-file headers against the
    declared license. Returns a drift entry tagged kind='source-header'
    with a classification field, or None when declared matches observed.

    Classification (positive-disclosure model — no entries are suppressed):
      "blocking"               — declared diverges from observed AND no
                                 documented multi-license rationale exists.
                                 Push gate refuses to ship.
      "multi-license-expected" — declared diverges from observed BUT the
                                 component is documented as a multi-license
                                 source tree (curation entry's
                                 classification field). The divergence is
                                 expected and the audit trail records it
                                 openly rather than suppressing it.
                                 Push gate ignores these.

    Expression-aware: if declared is "Apache-2.0 OR MIT" and we observe
    "Apache-2.0" markers in source files, that's a match (one branch of
    the dual is satisfied). Mismatch is when NO observed SPDX ID overlaps
    with any declared id after WITH-clause + GPL-suffix normalization.

    Backward compat: the legacy `skip_kinds: ["source-header"]` curation
    field is still honored — treated as classification="multi-license-
    expected" with no rationale upgrade.
    """
    if not file_evidence or license_info["kind"] == "none":
        return None

    def norm(x: str) -> str:
        x = x.split(" WITH ")[0]
        return x.replace("-or-later", "").replace("-only", "").strip().lower()

    declared_ids = license_info["all_ids"] or [license_info["value"]]
    declared_norm = {norm(d) for d in declared_ids if d}

    # Aggregate observed ids across all files. Expand expressions
    # ("Apache-2.0 OR MIT" → {"apache-2.0", "mit"}) so any matching
    # branch counts.
    observed: set[str] = set()
    for entry in file_evidence:
        for sid in entry.get("spdx", []):
            for part in re.split(r"\s+(?:OR|AND)\s+", sid, flags=re.IGNORECASE):
                observed.add(norm(part))

    # No divergence -> no entry at all (clean match).
    if declared_norm & observed:
        return None

    # Divergence detected. Classify based on curation log.
    curation = _load_drift_curation()
    key = f"{component.get('name', '')}@{component.get('version', '')}"
    entry = curation.get(key) or {}
    classification = "blocking"
    rationale = ""
    effective_license = ""
    if entry:
        # Modern field: explicit classification + rationale
        if "classification" in entry:
            classification = "multi-license-expected" if entry["classification"] in (
                "multi-license-source-tree", "multi-license-expected"
            ) else "blocking"
            rationale = entry.get("rationale", "")
            effective_license = entry.get("effective_license", "")
        # Legacy field: skip_kinds=["source-header"] implies multi-license-expected
        elif "source-header" in entry.get("skip_kinds", []):
            classification = "multi-license-expected"
            rationale = entry.get("rationale", "")

    return {
        "kind": "source-header",
        "classification": classification,
        "purl": component.get("purl", ""),
        "name": component.get("name", ""),
        "version": component.get("version", ""),
        "declared": license_info["value"],
        "detected": ", ".join(sorted(observed)),
        "evidence_files": len(file_evidence),
        "rationale": rationale,
        "effective_license": effective_license,
    }


def detect_drift(component: dict, license_info: dict, source_text: str) -> Optional[dict]:
    """Quick drift heuristic: declared SPDX vs what the source LICENSE looks
    like. Returns a drift-report entry or None."""
    if not source_text or license_info["kind"] == "none":
        return None
    declared = license_info["value"]
    text_lower = source_text[:5000].lower()

    # Curation log: skip drift detection for known-deliberate overrides.
    curation = _load_drift_curation()
    key = f"{component.get('name', '')}@{component.get('version', '')}"
    if key in curation:
        return None

    # Map of "obviously this license" content fingerprints. Order matters
    # for the early-exit case below — more-specific fingerprints first.
    # Unicode-3.0 must precede MIT because Unicode-3.0 contains the
    # phrase "permission is hereby granted, free of charge" verbatim
    # inside its longer body; without the explicit Unicode-3.0 match
    # ICU/Unicode crates would all false-positive as MIT.
    fingerprints = [
        ("Unicode-3.0", "unicode license v3"),
        ("Unicode-3.0", "unicode, inc. license v3"),
        # Rust ecosystem dual-license boilerplate — common to many
        # rust-lang crates that bundle both Apache + MIT. Must precede
        # the bare Apache and BSD-3 matches so the dual is detected.
        ("Apache-2.0 OR MIT", "rust project is dual-licensed under apache 2.0 and mit"),
        ("GPL-3.0", "gnu general public license\n                       version 3"),
        ("GPL-2.0", "gnu general public license\n                       version 2"),
        ("LGPL-2.1", "gnu lesser general public license\n                       version 2.1"),
        ("Apache-2.0", "apache license\n                           version 2.0"),
        ("MIT", "permission is hereby granted, free of charge"),
        ("BSD-3-Clause", "redistribution and use in source and binary forms"),
        ("ISC", "permission to use, copy, modify, and/or distribute"),
        ("MPL-2.0", "mozilla public license version 2.0"),
        ("PSF-2.0", "python software foundation license"),
    ]
    detected_set: list[str] = []
    for sid, fp in fingerprints:
        if fp in text_lower and sid not in detected_set:
            detected_set.append(sid)
    if not detected_set:
        return None

    # Normalize declared id for comparison: strip GPL-style suffixes and
    # SPDX exception clauses (e.g., "Apache-2.0 WITH LLVM-exception"
    # normalizes to "apache-2.0" so the WITH-clause doesn't cause drift).
    def norm(x: str) -> str:
        x = x.split(" WITH ")[0]
        return x.replace("-or-later", "").replace("-only", "").strip().lower()

    declared_norm = norm(declared)
    declared_ids_norm = [norm(d) for d in license_info["all_ids"]]
    detected_norm = [norm(d) for d in detected_set]

    # Expand dual-license detection into its component ids for matching.
    # "Apache-2.0 OR MIT" in detected expands to both ids individually.
    expanded_detected: set[str] = set()
    for d in detected_norm:
        for part in re.split(r"\s+or\s+|\s+and\s+", d):
            expanded_detected.add(part.strip())

    # Pass if any declared id matches any detected id (post-expansion).
    candidates = declared_ids_norm or [declared_norm]
    if any(d in expanded_detected for d in candidates):
        return None

    return {
        "kind": "license-file",
        "purl": component.get("purl", ""),
        "name": component.get("name", ""),
        "version": component.get("version", ""),
        "declared": declared,
        "detected": ", ".join(detected_set),
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

    # Supplemental bundled-component licenses: some wheels statically link a
    # vendored library whose own LICENSE ships in neither the wheel nor the
    # sdist (e.g. libffi inside cffi's Windows wheel). We redistribute the
    # linked object code, so its license text is reproduced here verbatim from
    # a curated source. (Till Jaeger review.)
    body = _append_bundled_licenses(component, body, cache_dir, no_cache)

    # Component-authored copyrights come from source-file headers + curated
    # seed. The license BODY is also mined (an MIT/BSD LICENSE often states the
    # component's own copyright), but license-DOCUMENT boilerplate (FSF on a GPL
    # text, unfilled templates) is filtered so it can't masquerade as the
    # component's copyright. (Till Jaeger review.)
    body_copyrights = [
        c for c in harvest_copyrights([body]) if not _is_license_text_copyright(c)
    ]
    copyrights = harvest_copyrights(source_headers, seed=copyright_seed + body_copyrights)
    copyrights = sanitize_list(copyrights)

    # Drift detection (LICENSE-file kind — the v1 check)
    drift = detect_drift(component, license_info, body)
    if drift:
        report["drift"] = drift

    _write_enrichment(component, body, copyrights, license_info)
    _write_scan_coverage(component, plan, source_headers)

    # In-pipeline evidence pass — cache-only walk for SPDX-License-Identifier
    # markers. Fast path (no fresh downloads); coverage of any given component
    # depends on whether its source tarball is in the cache (filled by either
    # prior enrich runs of the same component or by the offline deep scan).
    cached_loc = _resolve_cached_tarball(plan, cache_dir)
    if cached_loc is not None:
        tarball_url, tarball_fmt, tarball_prefix = cached_loc
        file_evidence = scan_cached_tarball_for_spdx(
            tarball_url, tarball_prefix, cache_dir, fmt=tarball_fmt
        )
        if file_evidence:
            # Sanitize file paths defensively — should already be relative,
            # but a malformed tarball entry could leak something unwelcome.
            for entry in file_evidence:
                entry["path"] = sanitize(entry.get("path", ""))
            _write_evidence(component, file_evidence)
            report["evidence_files"] = len(file_evidence)
            # Source-header drift — additive to the existing license-file
            # drift check. Both can fire for the same component and both
            # land in drift-report.<platform>.txt (different kinds, distinguishable).
            sh_drift = detect_source_header_drift(component, license_info, file_evidence)
            if sh_drift:
                # Stash alongside the v1 drift entry so report writer
                # captures both. List form lets a component carry one of
                # each kind without losing data.
                if drift:
                    report["drift"] = [drift, sh_drift]
                else:
                    report["drift"] = sh_drift

    report["status"] = "enriched"
    report["source_tag"] = source_tag
    return component, report


def _probe_github_homepage_license(
    homepage: str, cache_dir: Path, no_cache: bool
) -> dict[str, bytes]:
    """Probe a github homepage URL for LICENSE-like files. Returns {} if the URL
    isn't a github repo or nothing is found. Used as an upstream fallback when a
    PyPI artifact ships no license file of its own. (Till Jaeger review.)"""
    if not homepage.startswith("https://github.com/"):
        return {}
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/?#]+)(?:/tree/([^/?#]+))?", homepage
    )
    if not m:
        return {}
    owner, repo, ref = m.group(1), m.group(2), m.group(3) or "main"
    base = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}"
    try:
        return fetch_single_file_probes(base, cache_dir, no_cache)
    except Exception:
        return {}


def _fetch_artifacts(
    plan: dict, cache_dir: Path, no_cache: bool
) -> tuple[dict[str, bytes], list[str], list[str]]:
    """Return (license_files, source_headers, copyright_seed) per plan kind."""
    kind = plan["kind"]
    if kind == "tarball":
        files = fetch_tarball_license_files(plan["url"], plan.get("path_prefix", ""), cache_dir, no_cache)
        headers = fetch_tarball_source_headers(plan["url"], plan.get("path_prefix", ""), cache_dir, no_cache)
        return files, headers, []
    if kind == "github-release-tarball":
        # Try each tag candidate until one resolves to a real tarball.
        # Added 2026-05-22 (Till Jaeger Q3): for torch-family packages with
        # PEP 440 +local segments (+cu128 etc.) the PyPI path is a dead end;
        # the canonical source tree lives at the GitHub release tag tarball
        # and contains every vendored sub-tree we redistribute via the wheel.
        owner = plan["owner"]
        repo = plan["repo"]
        last_error: Optional[Exception] = None
        for tag in plan["tag_candidates"]:
            url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{urllib.parse.quote(tag)}.tar.gz"
            # GitHub release tarballs unpack to <repo>-<tag>/ — prefix-strip-friendly
            prefix = f"{repo}-{tag.lstrip('v')}/"
            try:
                files = fetch_tarball_license_files(url, prefix, cache_dir, no_cache)
                headers = fetch_tarball_source_headers(url, prefix, cache_dir, no_cache)
                return files, headers, []
            except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError) as e:
                last_error = e
                continue
        # All tag candidates failed — fall back to the github-raw single-file
        # probe against the upstream homepage, matching the prior behaviour.
        upstream = plan.get("upstream_source_url", "")
        if upstream.startswith("https://github.com/"):
            m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)", upstream)
            if m:
                base = f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/main"
                return fetch_single_file_probes(base, cache_dir, no_cache), [], []
        if last_error:
            raise last_error
        return {}, [], []
    if kind == "npm-via-metadata":
        files = fetch_npm_via_metadata(plan["metadata_url"], plan.get("path_prefix", ""), cache_dir, no_cache)
        # Harvest source-file headers too — captures copyrights that live only
        # in source headers (e.g. "Tauri Programme within The Commons
        # Conservancy"), not in the LICENSE body, so the audit's source-header
        # copyright check is satisfied. (Till Jaeger review.)
        headers = fetch_npm_source_headers(plan["metadata_url"], cache_dir, no_cache)
        return files, headers, []
    if kind == "pypi-via-metadata":
        try:
            files = fetch_pypi_via_metadata(plan["metadata_url"], cache_dir, no_cache)
            # Also harvest source-file headers — catches vendored attributions
            # (e.g. Mark Adler's zlib copyright inside grpcio, Department of
            # Arts and Culture inside pyworld) that live in .c/.py header
            # comments and never appear in the package LICENSE file.
            headers = fetch_pypi_source_headers(plan["metadata_url"], cache_dir, no_cache)
            # Some PyPI distributions ship NO license file in the wheel/sdist
            # (e.g. comfyui-workflow-templates-*). Without it, select_license_text
            # falls back to the generic SPDX template with unfilled
            # `<year> <copyright holders>`. When the artifact carries no license
            # file, probe the canonical GitHub repo for the real LICENSE — same
            # upstream-fallback principle as the HF-mirror path. (Till Jaeger.)
            if not files:
                gh = _probe_github_homepage_license(
                    plan.get("homepage_fallback", ""), cache_dir, no_cache
                )
                if gh:
                    files = gh
            return files, headers, []
        except (urllib.error.HTTPError, RuntimeError):
            # Package not on PyPI at all — fall back to GitHub homepage.
            gh = _probe_github_homepage_license(
                plan.get("homepage_fallback", ""), cache_dir, no_cache
            )
            if gh:
                return gh, [], []
            raise
    if kind == "hf-probe":
        files = fetch_single_file_probes(plan["base_url"], cache_dir, no_cache)
        # Till Jaeger Q1 fix (2026-05-22): when the HF mirror has no LICENSE
        # file (true for every memescreamer model mirror — they only carry
        # weight files), fall back to the canonical upstream repo. This is
        # how the NVIDIA copyright line for BigVGAN — and every other
        # AI-Model supplier's copyright — gets into NOTICES.<platform>.txt without
        # us having to hand-curate each one.
        if not files and plan.get("upstream_source_url"):
            upstream = plan["upstream_source_url"]
            m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)(?:/tree/([^/?#]+))?", upstream)
            if m:
                owner, repo, ref = m.group(1), m.group(2), m.group(3) or "main"
                base = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}"
                files = fetch_single_file_probes(base, cache_dir, no_cache)
        return files, [], []
    if kind == "gh-raw-probe":
        return fetch_single_file_probes(plan["base_url"], cache_dir, no_cache), [], []
    if kind == "system-curated":
        # Download tarball, extract listed license + notice files first
        # (curation map declares exact order), THEN walk for any other
        # LICENSE/COPYING/NOTICE files in the tree to capture bundled-
        # component attributions (CPython's Modules/expat/COPYING,
        # Modules/_ctypes/libffi/LICENSE, ffmpeg's per-codec NOTICE
        # entries, etc.). Without this, packages that bundle third-party
        # code lose those attributions even though we ship the bundled
        # binaries inside our distribution.
        blob = cached_fetch(plan["url"], cache_dir, no_cache)
        files: dict[str, bytes] = {}
        prefix = plan.get("path_prefix", "")
        listed_set = set(plan["license_files"]) | set(plan.get("notice_files", []))
        bundled_files: dict[str, bytes] = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                # Pass 1: explicit listed files (curated order matters).
                for lic_name in plan["license_files"] + plan.get("notice_files", []):
                    candidate = prefix + lic_name if prefix else lic_name
                    try:
                        member = tf.getmember(candidate)
                    except KeyError:
                        continue
                    f = tf.extractfile(member)
                    if f is not None:
                        files[lic_name] = f.read()
                # Pass 2: any OTHER LICENSE-pattern file in the tree (we
                # call these "bundled" because they live in subdirectories
                # alongside vendored third-party code). Skip already-listed
                # paths so we don't double-include.
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    rel = member.name
                    if prefix and rel.startswith(prefix):
                        rel = rel[len(prefix):]
                    if rel in listed_set:
                        continue
                    if not LICENSE_FILE_RE.search(rel):
                        continue
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    try:
                        bundled_files[rel] = f.read()
                    except Exception:
                        continue
        except tarfile.TarError as e:
            raise RuntimeError(f"system-tool tarball error: {e}") from e

        # Build the ordered body: listed primary + listed notice + bundled
        # attribution. The latter is sorted by path for deterministic
        # output across re-runs.
        ordered_text_parts: list[str] = []
        for lic_name in plan["license_files"]:
            if lic_name in files:
                text = files[lic_name].decode("utf-8", errors="replace")
                ordered_text_parts.append(f"=== {lic_name} ({plan.get('primary_license_id', '')}) ===\n\n{text}")
        for notice_name in plan.get("notice_files", []):
            if notice_name in files:
                text = files[notice_name].decode("utf-8", errors="replace")
                ordered_text_parts.append(f"=== NOTICE ({notice_name}) ===\n\n{text}")
        for rel in sorted(bundled_files):
            text = bundled_files[rel].decode("utf-8", errors="replace")
            tag = "NOTICE" if NOTICE_FILE_RE.search(rel) else "BUNDLED-ATTRIBUTION"
            ordered_text_parts.append(f"=== {tag} ({rel}) ===\n\n{text}")

        # Harvest source-file headers from the same tarball so recorded
        # copyrights include the real per-file authors (ffmpeg's Bellard/
        # Niedermayer, the Xiph / LAME / zlib authors, CPython's contributors,
        # and the autotools FSF lines that genuinely ship in the source tree).
        # Without this the audit's source-header copyright check fails on
        # system-curated components. License-TEXT FSF boilerplate (the GPL/LGPL
        # license documents themselves) is still filtered separately at the
        # harvest call site — that is Till's actual 3a complaint, and it stays
        # fixed. (Till Jaeger review.)
        try:
            sys_headers = fetch_tarball_source_headers(plan["url"], prefix, cache_dir, no_cache)
        except Exception:
            sys_headers = []
        if ordered_text_parts:
            concat = "\n\n".join(ordered_text_parts)
            # Encode as a single synthetic LICENSE entry so select_license_text picks it
            return ({"_SYSTEM_CURATED_BODY_": concat.encode("utf-8")},
                    sys_headers,
                    plan.get("copyright_seed", []))
        return {}, sys_headers, plan.get("copyright_seed", [])
    return {}, [], []


def _write_evidence(component: dict, file_evidence: list[dict]) -> None:
    """Mutate component in place: populate component.evidence (CycloneDX 1.5
    canonical) with concluded SPDX ids aggregated from source-file headers,
    plus per-file detail under the com.raidio.evidence.files property
    (base64-encoded JSON; same custom-property pattern v1 used for
    licenseText on dual-license entries)."""
    if not file_evidence:
        return

    # Aggregate concluded SPDX ids across all observed files. Sorted for
    # deterministic re-runs (set order is implementation-defined).
    aggregated: set[str] = set()
    for entry in file_evidence:
        for sid in entry.get("spdx", []):
            aggregated.add(sid)
    if not aggregated:
        return

    # Per-component bom-ref fragment used to keep evidence bom-refs
    # locally unique. CycloneDX requires unique bom-refs across the BOM
    # but allows arbitrary strings; sha256 of purl trimmed to 8 hex
    # chars is collision-safe at our scale and stable across runs.
    purl = component.get("purl", "") or component.get("name", "")
    purl_hash = hashlib.sha256(purl.encode("utf-8")).hexdigest()[:8]

    licenses_block = []
    for sid in sorted(aggregated):
        licenses_block.append(
            {
                "license": {"id": sid} if " " not in sid else {"expression": sid},
                "bom-ref": f"evidence-{purl_hash}-{sid.replace(' ', '_')}",
            }
        )

    evidence = component.setdefault("evidence", {})
    evidence["licenses"] = licenses_block

    # Per-file detail: keep small. Path + spdx ids + first-line number,
    # base64'd JSON to avoid bloating the SBOM with deeply nested
    # structures that hurt readability of the surrounding components.
    file_list_json = json.dumps(file_evidence, separators=(",", ":"), sort_keys=True)
    file_list_b64 = base64.b64encode(file_list_json.encode("utf-8")).decode("ascii")

    props = component.setdefault("properties", [])
    # Replace any existing entry — idempotent re-runs.
    props[:] = [p for p in props if p.get("name") != "com.raidio.evidence.files"]
    props.append({"name": "com.raidio.evidence.files", "value": file_list_b64})


def _write_scan_coverage(component: dict, plan: dict, source_headers: list[str]) -> None:
    """Tag the component with its scan-coverage tier.

    Added 2026-05-22 per Till Jaeger Q3 follow-up. Values:
      license-only  — only the root LICENSE-named file(s) were probed.
                       True for: hf-probe, gh-raw-probe, npm-via-metadata,
                       pypi-via-metadata after wheel-fallback (no source),
                       system-curated (curation map names specific files).
      sampled       — tarball walked for source-header copyrights, capped
                       at 300 files / 50 lines each.
      exhaustive    — full source-tree walk (only set by the offline
                       sbom_deep_scan.py pass).

    A reviewer can filter `com.raidio.scan-coverage == license-only` to find
    every component where the scan was shallow enough that vendored sub-tree
    copyrights might have been missed — useful triage for large multi-vendor
    Python wheels in particular.
    """
    kind = plan.get("kind", "")
    if kind in ("hf-probe", "gh-raw-probe", "npm-via-metadata", "system-curated"):
        coverage = "license-only"
    elif kind in ("tarball", "github-release-tarball"):
        coverage = "sampled" if source_headers else "license-only"
    elif kind == "pypi-via-metadata":
        # If we got source headers, the sdist fetch succeeded and we walked
        # it. Empty source_headers means we fell back to the github-raw probe
        # path which is single-file-LICENSE only.
        coverage = "sampled" if source_headers else "license-only"
    else:
        coverage = "license-only"
    props = component.setdefault("properties", [])
    props[:] = [p for p in props if p.get("name") != "com.raidio.scan-coverage"]
    props.append({"name": "com.raidio.scan-coverage", "value": coverage})

    # For system-curated components (ffmpeg, CPython) that embed multiple
    # constituent LICENSE bodies (ffmpeg's COPYING.GPLv3 + GPLv2 + LGPLv2.1
    # + LGPLv3 etc.), expose the file list so a reviewer can see the
    # multi-license source-tree reality without having to grep the
    # base64-encoded license.text body. Added 2026-05-22 per Till Jaeger
    # Q2 follow-up — the prior 5-way `AND` license expression on ffmpeg
    # misrepresented these as parallel licenses; collapsing to a single
    # GPL-3.0-or-later effective license was correct, but the constituent
    # bodies still ship in the SBOM for attribution and the property below
    # makes that fact discoverable without decoding the body.
    if plan.get("kind") == "system-curated":
        bundled = list(plan.get("license_files", [])) + list(plan.get("notice_files", []))
        if bundled:
            props[:] = [p for p in props if p.get("name") != "com.raidio.bundled-license-texts"]
            props.append({
                "name": "com.raidio.bundled-license-texts",
                "value": ", ".join(bundled),
            })


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
# NOTICES.<platform>.txt rendering
# ---------------------------------------------------------------------------


NOTICES_HEADER = (
    "rAIdio.bot — Third-Party Notices\n"
    "Plain-text rendering derived from sbom.<platform>.json (CycloneDX 1.5).\n"
    "Per-component verbatim license texts + copyright statements.\n"
    "Generated by tools/sbom_enrich.py at release time.\n"
    "\n"
    "═══════════════════════════════════════════════════════════════════════════\n"
)


NOTICES_MD_HEADER = (
    "# rAIdio.bot — Third-Party Notices\n\n"
    "Markdown rendering derived from `sbom.<platform>.json` (CycloneDX 1.5).\n"
    "Per-component verbatim license texts, copyright statements, and\n"
    "(when populated) file-level license evidence.\n\n"
    "Generated by `tools/sbom_enrich.py` at release time. Re-run\n"
    "`tools/sbom_deep_scan.py` to refresh the file-level evidence sections.\n\n"
    "---\n\n"
)


def _md_anchor(name: str, version: str) -> str:
    """GitHub-style markdown auto-anchor: lowercase, alphanumeric+hyphen.
    Mirrors github.com's heading-anchor algorithm closely enough for our
    purposes (we don't have duplicate component names+versions).
    """
    slug = f"{name} {version}".lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug.strip())
    return slug


def render_notices_md(sbom: dict) -> str:
    """Markdown counterpart to render_notices. Same per-component data,
    rendered with markdown headers, code-fenced license bodies, and
    collapsible details for the per-file evidence list (which can be
    100+ files for large crates and would dominate the page if inlined).
    Added a clickable per-component TOC at the top 2026-05-22 per Till
    Jaeger Q4 follow-up — the rendered file is large and ad-hoc search
    in GitHub's renderer is brittle. GitHub renders this natively;
    mkdocs / pandoc / any markdown viewer handles it too."""
    components = sbom.get("components", [])
    # TOC: alphabetical by name (case-insensitive), each line a clickable
    # anchor link to the per-component section below.
    toc_lines: list[str] = ["## Components\n\n"]
    toc_lines.append(f"_{len(components)} components, alphabetical by name. Click to jump._\n\n")
    sorted_for_toc = sorted(components, key=lambda c: (c.get("name", "").lower(), c.get("version", "")))
    for c in sorted_for_toc:
        n = c.get("name", "?")
        v = c.get("version", "?")
        anchor = _md_anchor(n, v)
        toc_lines.append(f"- [`{n}` `{v}`](#{anchor})\n")
    toc_lines.append("\n---\n\n")
    parts: list[str] = [NOTICES_MD_HEADER, "".join(toc_lines)]
    for c in components:
        name = c.get("name", "?")
        version = c.get("version", "?")
        purl = c.get("purl", "")
        homepage = get_homepage(c)
        license_info = get_license_info(c)
        license_label = license_info["value"] or "Unknown"

        # Decode license text (same path as render_notices)
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
            for p in c.get("properties", []):
                if p.get("name") == "com.raidio.licenseText":
                    try:
                        text = base64.b64decode(p["value"]).decode("utf-8", errors="replace")
                        break
                    except Exception:
                        pass

        copyright_text = c.get("copyright", "")

        # Decode file-level evidence (com.raidio.evidence.files property)
        file_evidence: list[dict] = []
        for p in c.get("properties", []):
            if p.get("name") == "com.raidio.evidence.files":
                try:
                    file_evidence = json.loads(base64.b64decode(p["value"]))
                except Exception:
                    pass
                break

        evidence_aggregate: list[str] = []
        for lic in c.get("evidence", {}).get("licenses", []) or []:
            inner = lic.get("license", {})
            sid = inner.get("id") or inner.get("expression", "")
            if sid:
                evidence_aggregate.append(sid)

        parts.append(f"## {name} {version}\n\n")
        parts.append("| Field | Value |\n|---|---|\n")
        parts.append(f"| License | `{license_label}` |\n")
        parts.append(f"| Homepage | {homepage or '(none)'} |\n")
        parts.append(f"| PURL | `{purl}` |\n")
        if evidence_aggregate:
            parts.append(f"| File-level evidence (concluded SPDX) | {', '.join(f'`{x}`' for x in evidence_aggregate)} |\n")
        if file_evidence:
            parts.append(f"| Files with license markers | {len(file_evidence)} |\n")
        parts.append("\n")

        if copyright_text:
            parts.append("### Copyright\n\n```\n")
            parts.append(copyright_text)
            parts.append("\n```\n\n")

        if text:
            parts.append("### License text\n\n```\n")
            # Strip trailing newlines to keep code-block tight; markdown
            # renderers add their own spacing after the closing fence.
            parts.append(text.rstrip("\n"))
            parts.append("\n```\n\n")
        else:
            parts.append("### License text\n\n_License text not embedded; see homepage._\n\n")

        if file_evidence:
            parts.append(
                f"<details><summary>File-level evidence ({len(file_evidence)} files)</summary>\n\n"
            )
            parts.append("| Path | SPDX | Kind | Line |\n|---|---|---|---|\n")
            for entry in file_evidence:
                path = entry.get("path", "")
                spdx = ", ".join(entry.get("spdx", []))
                kind = entry.get("kind", "spdx-header")
                line = entry.get("line", "")
                parts.append(f"| `{path}` | `{spdx}` | {kind} | {line} |\n")
            parts.append("\n</details>\n\n")

        parts.append("---\n\n")

    return "".join(parts)


def render_notices(sbom: dict) -> str:
    """Render NOTICES.<platform>.txt with a per-component table-of-contents prepended.
    The TOC was added 2026-05-22 per Till Jaeger Q4 follow-up — the file has
    grown past 190k lines and ad-hoc search is brittle without an index.
    Format: alphabetical-by-name TOC at the top, each entry naming the line
    where the COMPONENT: header for that entry begins, then the per-component
    blocks. Line numbers are computed AFTER body rendering so they're stable.
    """
    blocks: list[tuple[str, str, str]] = []  # (name, version, rendered_block)
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
        blocks.append((name, version, block))

    # Build the TOC. We need each component's line number in the final file.
    # The final file is: HEADER + TOC + blocks. So a block's line number =
    # HEADER lines + TOC lines + lines-in-previous-blocks + 1 (for the
    # COMPONENT header line itself). We compute the TOC iteratively.
    header_lines = NOTICES_HEADER.count("\n")
    toc_intro = (
        "TABLE OF CONTENTS\n"
        "─────────────────\n"
        f"Total components: {len(blocks)}. Alphabetical by name; line number is\n"
        "where the `COMPONENT:` header for that entry begins.\n"
        "\n"
    )
    toc_intro_lines = toc_intro.count("\n")
    toc_outro = "═══════════════════════════════════════════════════════════════════════════\n\n"
    toc_outro_lines = toc_outro.count("\n")

    # Sort blocks alphabetically (case-insensitive on name) for the TOC.
    indexed = sorted(enumerate(blocks), key=lambda iv: (iv[1][0].lower(), iv[1][1]))
    # Each TOC line is one line plus its trailing \n. Approximate length cap
    # so all TOC entries align cleanly: pad name+version to a fixed width.
    longest = max((len(f"{n} {v}") for n, v, _ in blocks), default=40)
    name_col = max(longest + 2, 30)
    toc_entry_lines = len(blocks)  # one line per entry
    toc_total_lines = toc_intro_lines + toc_entry_lines + toc_outro_lines

    # Compute the line where each block starts in the final file.
    # Header is at lines 1..header_lines (next line after = TOC start).
    # TOC occupies header_lines+1 .. header_lines+toc_total_lines.
    # First block starts at header_lines + toc_total_lines + 1.
    base = header_lines + toc_total_lines + 1
    block_lines = [b.count("\n") for _, _, b in blocks]
    block_start_lines = []
    cursor = base
    for n_lines in block_lines:
        block_start_lines.append(cursor)
        cursor += n_lines

    # Map original-index → line number, then emit TOC sorted alphabetically.
    line_by_orig = {i: line for i, line in enumerate(block_start_lines)}
    toc_lines: list[str] = []
    for orig_idx, (n, v, _) in indexed:
        label = f"{n} {v}"
        ln = line_by_orig[orig_idx]
        toc_lines.append(f"  {label.ljust(name_col)} line {ln}\n")
    toc_body = toc_intro + "".join(toc_lines) + "\n" + toc_outro

    parts: list[str] = [NOTICES_HEADER, toc_body]
    for _, _, b in blocks:
        parts.append(b)
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

    # Evidence pass summary — populated from the in-pipeline cache-only walk.
    # Components without a cached source tarball (HF models, GitHub-raw probes
    # before the offline deep scan has filled the cache) silently contribute
    # zero. Coverage gradually grows as the offline scan runs.
    lines.append("")
    lines.append("Evidence pass (file-level SPDX markers from cached tarballs):")
    components_with_evidence = sum(1 for r in results if r.get("evidence_files"))
    total_files = sum(int(r.get("evidence_files") or 0) for r in results)
    enriched = sum(1 for r in results if r["status"] == "enriched")
    coverage_pct = (100.0 * components_with_evidence / enriched) if enriched else 0.0
    lines.append(f"  components with evidence:   {components_with_evidence} / {enriched} ({coverage_pct:.1f}% of enriched)")
    lines.append(f"  source files contributing:  {total_files}")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_drift_report(drift_path: Path, results: list[dict]) -> None:
    """Write drift-report.<platform>.txt with positive-disclosure classification.

    Every divergence is recorded, classified, and rendered. Two
    classifications exist:
      blocking               — declared SPDX disagrees with observed SPDX
                               AND the divergence is NOT documented in
                               tools/sbom_drift_curation.json. The next
                               push is refused until this is either
                               curated (with rationale) or corrected.
      multi-license-expected — declared SPDX disagrees with observed SPDX
                               but the component is documented as a
                               multi-license source tree with rationale.
                               The next push is NOT blocked by these
                               (they're audit-trail records, not gates).

    Compare to the previous "skip_kinds" suppression model: nothing is
    hidden. Adversarial counsel reading drift-report.<platform>.txt sees every
    detected divergence and the documented reasoning for treating any
    given one as expected.
    """
    drift_entries: list[dict] = []
    for r in results:
        d = r.get("drift")
        if isinstance(d, list):
            drift_entries.extend(d)
        elif isinstance(d, dict):
            drift_entries.append(d)

    # Classify each entry. license-file kind doesn't have a classification
    # field yet — those are always treated as blocking (they're stronger
    # evidence than source-header, since they fingerprint the full LICENSE
    # body, not individual file markers).
    for e in drift_entries:
        if e.get("kind") == "source-header":
            e.setdefault("classification", "blocking")
        else:
            e["classification"] = "blocking"

    blocking = [e for e in drift_entries if e.get("classification") == "blocking"]
    expected = [e for e in drift_entries if e.get("classification") == "multi-license-expected"]

    if not drift_entries:
        drift_path.write_text(
            "# Drift report — no entries.\n# Next push is unblocked.\n",
            encoding="utf-8",
        )
        return

    lines = [
        "rAIdio.bot SBOM enrichment — license drift report",
        "=" * 64,
        "",
        "WHAT THIS FILE IS (FOSS-compliance review follow-up, 2026-05-22).",
        "",
        "drift-report.<platform>.txt is a TRANSPARENCY LOG, not a missing-components",
        "list. Presence in this report does NOT mean a component is missing",
        "from NOTICES.<platform>.txt or the SBOM — every component listed here IS in",
        "both. This file enumerates the cases where what we declare as the",
        "component's license differs from what our deep-scanner observes",
        "in the source tree, with one of two outcomes:",
        "",
        "  * multi-license-expected — the source tree contains files with",
        "    licenses that are NOT the same as the declared package",
        "    license, but this is by design: the package vendors third-",
        "    party code (e.g. grpcio vendors zlib + abseil + boringssl",
        "    fragments) whose original per-file licenses we preserve.",
        "    These entries are documented + curated and do NOT block the",
        "    next release push.",
        "  * blocking — divergence not yet curated. The next push is",
        "    refused until either curated (with rationale in",
        "    tools/sbom_drift_curation.json) or corrected (in",
        "    tools/generate_sbom.py).",
        "",
        "Look in NOTICES.<platform>.txt to see what we actually preserve for any",
        "component listed here; the TOC at the top of that file lists",
        "every component with its line number for quick lookup.",
        "",
        "=" * 64,
        "",
        f"Total entries:                 {len(drift_entries)}",
        f"  blocking:                    {len(blocking)}  (push refuses to ship while > 0)",
        f"  multi-license-expected:      {len(expected)}  (audit-trail only; push not blocked)",
        "",
        "license-file detector: fingerprints the LICENSE body content against",
        "  canonical SPDX text. Strong evidence — always classified as blocking.",
        "source-header detector: aggregates SPDX-License-Identifier markers",
        "  observed in actual source files. May be blocking or",
        "  multi-license-expected depending on tools/sbom_drift_curation.json.",
        "",
        "Adversarial-discovery posture: nothing is suppressed. Every divergence",
        "is recorded here with its classification. multi-license-expected",
        "entries carry a rationale field documenting why the divergence is",
        "expected (typically: the source tree IS multi-licensed, and the",
        "effective license of the shipped binary is determined by build",
        "configuration rather than by every individual file header).",
        "",
        "Audit workflow:",
        "  - blocking entries must be either curated (add classification field",
        "    in tools/sbom_drift_curation.json with rationale) or corrected",
        "    (update tools/generate_sbom.py for the right SPDX expression).",
        "  - multi-license-expected entries need no action; they are recorded",
        "    for transparency and propagate into the SBOM as the",
        "    com.raidio.bundled-licenses-detected property.",
        "",
        "While the blocking count is > 0, steam/push.ps1 refuses to push.",
        "=" * 64,
        "",
    ]

    for class_label, bucket in (("blocking", blocking), ("multi-license-expected", expected)):
        if not bucket:
            continue
        lines.append(f"--- {class_label} ({len(bucket)}) ---")
        lines.append("")
        for e in bucket:
            lines.append(f"  {e['name']} {e['version']}  [kind={e.get('kind', 'license-file')}]")
            lines.append(f"    purl:     {e['purl']}")
            lines.append(f"    declared: {e['declared']}")
            lines.append(f"    detected: {e['detected']}")
            if e.get("effective_license"):
                lines.append(f"    effective_license: {e['effective_license']}")
            if e.get("rationale"):
                # Wrap long rationales for readability
                wrapped = e["rationale"]
                lines.append(f"    rationale: {wrapped}")
            if e.get("kind") == "license-file" and e.get("evidence"):
                lines.append("    evidence (first 500 chars):")
                for ln in e["evidence"].splitlines()[:10]:
                    lines.append(f"      | {ln}")
            elif e.get("kind") == "source-header":
                lines.append(f"    files with SPDX markers: {e.get('evidence_files', '?')}")
            lines.append("")

    drift_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, help="Path to input CycloneDX 1.5 JSON")
    parser.add_argument("--output", required=True, help="Path to output enriched sbom.<platform>.json (sbom-repo root)")
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
    parser.add_argument(
        "--platform",
        default="",
        help="Platform label (e.g. windows, linux). When set, the sibling "
        "NOTICES/enrich-report/drift-report files are written per-platform "
        "(NOTICES.<platform>.txt etc.) so Windows and Linux never overwrite "
        "each other in the public sbom repo. Empty = legacy unsuffixed names.",
    )
    args = parser.parse_args()

    # Per-platform infix for the sibling artefacts (NOTICES / reports). The
    # enriched SBOM itself is named by the caller via --output (e.g.
    # sbom.windows.json); the siblings key off this label to match.
    plat_infix = f".{args.platform}" if args.platform else ""

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

    # NOTICES.<platform>.txt + NOTICES.<platform>.md (parallel renderings of the same data —
    # plain text for offline / minimal-tooling consumption, markdown for
    # GitHub / mkdocs / pandoc / human review with collapsible sections).
    notices_path = sbom_out_path.parent / f"NOTICES{plat_infix}.txt"
    notices_path.write_text(render_notices(sbom), encoding="utf-8")
    print(f"[enrich] Wrote {notices_path}", file=sys.stderr)
    notices_md_path = sbom_out_path.parent / f"NOTICES{plat_infix}.md"
    notices_md_path.write_text(render_notices_md(sbom), encoding="utf-8")
    print(f"[enrich] Wrote {notices_md_path}", file=sys.stderr)

    # Reports
    report_path = sbom_out_path.parent / f"enrich-report{plat_infix}.txt"
    drift_path = sbom_out_path.parent / f"drift-report{plat_infix}.txt"
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
