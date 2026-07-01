#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multiprocess call-chain compactor.
- Scans ../mcp_servers_repos for projects that contain a call_chains.json
- Processes each project in parallel (MAX_PROCS env, default: CPU count)
- Produces per-project outputs:
  - tool_codes_compact_v1.json  ({"p": "<project>", "m": {"<tool>": ["<code>", ...]}})
  - tool_codes_compact_v1.txt   (plain text for quick LLM paste)
"""
from __future__ import annotations

import os, json, re, hashlib
from pathlib import Path
from typing import Any, List, Dict, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

CODE_ROOT = Path("../mcp_servers_repos")
JSON_NAME = "call_chains.json"
OUT_JSON  = "tool_codes_compact_v1.json"
OUT_TXT   = "tool_codes_compact_v1.txt"

def N(s: str) -> str:
    # normalize: newlines, strip trailing spaces, remove BOM/NULL, and trim
    s = s.replace("\r\n","\n").replace("\r","\n")
    s = "\n".join(l.rstrip() for l in s.split("\n"))
    s = s.replace("\ufeff","").replace("\x00","")
    return s.strip()

H = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()

def C(n: Any, bag: List[str]) -> None:
    """Collect 'code' fields recursively from a call-chain tree with structure:
       { "code": "<src>", "calls": [ { ... }, ... ] }"""
    if isinstance(n, dict):
        v = n.get("code")
        if isinstance(v, str):
            q = N(v)
            if q:
                bag.append(q)
        c = n.get("calls")
        if isinstance(c, list):
            for x in c:
                C(x, bag)
    elif isinstance(n, list):
        for x in n:
            C(x, bag)

def process_one_project(project_dir: Path) -> Tuple[str, bool, str]:
    """Return (project_name, ok, message)"""
    try:
        ip = project_dir / JSON_NAME
        if not ip.exists():
            return project_dir.name, False, f"missing {JSON_NAME}"
        try:
            d = json.loads(ip.read_text(encoding="utf-8"))
        except Exception as e:
            return project_dir.name, False, f"bad JSON: {e}"

        cc = d.get("call_chains") or {}
        pj = d.get("project") or project_dir.name

        m: Dict[str, List[str]] = {}
        for t, r in cc.items():
            bag: List[str] = []
            C(r, bag)
            seen = set()
            u: List[str] = []
            for s in bag:
                h = H(s)
                if h in seen:
                    continue
                seen.add(h)
                u.append(s)
            if u:
                m[t] = u

        # write outputs
        oj = project_dir / OUT_JSON
        ot = project_dir / OUT_TXT

        oj.write_text(json.dumps({"p": pj, "m": m}, ensure_ascii=False, separators=(",",":")), encoding="utf-8")

        sep_t = "\n\n<<<TOOL>>>\n"
        sep_c = "\n---\n"
        chunks = []
        for t, codes in m.items():
            chunks.append(t + sep_c + sep_c.join(codes))
        ot.write_text(sep_t.join(chunks), encoding="utf-8")

        return project_dir.name, True, f"tools={len(m)}"
    except Exception as e:
        return project_dir.name, False, f"error: {e}"

def discover_projects(root: Path) -> List[Path]:
    # Prefer top-level dirs under code2; allow a fallback to rglob if not found.
    if not root.exists():
        return []
    dirs = [p for p in root.iterdir() if p.is_dir() and (p / JSON_NAME).exists()]
    if dirs:
        return dirs
    # Fallback: deep search (can be expensive on 10k repos; use only if needed)
    return [p.parent for p in root.rglob(JSON_NAME)]

def main() -> None:
    projects = discover_projects(CODE_ROOT)
    if not projects:
        print(f"[!] No projects with {JSON_NAME} under {CODE_ROOT}")
        return

    max_procs = int(os.environ.get("MAX_PROCS", os.cpu_count() or 4))
    print(f"Found {len(projects)} projects. Running with MAX_PROCS={max_procs}.")

    summary = {"processed": 0, "ok": 0, "failed": 0, "errors": {}}
    with ProcessPoolExecutor(max_workers=max_procs) as exe:
        fut2proj = {exe.submit(process_one_project, p): p for p in projects}
        for fut in as_completed(fut2proj):
            proj = fut2proj[fut]
            name, ok, msg = fut.result()
            summary["processed"] += 1
            if ok:
                summary["ok"] += 1
                print(f"[{name}] OK  {msg}")
            else:
                summary["failed"] += 1
                summary["errors"][name] = msg
                print(f"[{name}] FAILED  {msg}")

    # Write summary to top-level next to code2
    summary_path = CODE_ROOT.parent / "tool_codes_compact_v1__SUMMARY.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
