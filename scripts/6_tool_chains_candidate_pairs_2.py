#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate candidate tool pairs with OpenRouter-based semantic checks."""

import os
import json
import itertools
import time
import threading
import argparse
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from openai import OpenAI, APIError, APITimeoutError, APIConnectionError
import httpx
from tqdm import tqdm

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 1. Configuration ---

DEFAULT_ROOT_DIR = Path("../mcp_servers_repos")  # Default root directory containing mcp_server directories
MODEL_NAME = os.environ.get("OPENAI_MODEL", "x-ai/grok-4-fast")
ENDPOINT = os.environ.get("OPENAI_API_BASE", "https://openrouter.ai/api/v1")

# OpenRouter API Keys
API_KEY = "sk-or-v1-xxx"

MAX_WORKERS = max(4, os.cpu_count() or 10)  # Thread count, can be adjusted based on throughput
REQUEST_TIMEOUT = 120                       # Request timeout in seconds
MAX_RETRIES = 3                             # Maximum retry count per call
RETRY_BACKOFF = 2.0                         # Exponential backoff base

# --- 2. Phase-1 Prompt (Dual-Boolean) ---

PHASE_1_PROMPT_TEMPLATE = """
Decide whether the relationship between A and B exhibits:  
1. **Dataflow**: A writes or persists data that B reads or loads within the same resource or context.  
2. **Enablement**: A directly enables B's precondition to run or execute within the same session, tab, or context.

# Steps  

1. **Understand Context**: Analyze the scenario where A interacts with B to identify how A influences B.  
2. **Dataflow Analysis**:  
   - Confirm if A produces or modifies data (e.g., storage, database, file, buffer) that B subsequently accesses.  
   - Verify that both A and B operate within the same resource or context for data persistence.  
3. **Enablement Analysis**:  
   - Determine whether A directly triggers, fulfills, or initiates conditions required for B's execution.  
   - Ensure this enablement occurs in the same session, tab, or context.  
4. **Evaluate Results**:  
   - **"Dataflow only"**: If A creates or modifies data that B accesses without fulfilling preconditions.  
   - **"Enablement only"**: If A meets preconditions for B without involving data persistence.  
   - **"Both Dataflow and Enablement"**: If both conditions are satisfied.  
   - **"Neither"**: If neither condition is satisfied.

# Output Format  

Provide the results as JSON formatted as follows:  

{
  "dataflow": [true/false],
  "enablement": [true/false],
  "confidence_dataflow": [0-1],
  "confidence_enablement": [0-1],
  "dataflow_reason": "Detailed explanation (if true or uncertain).",
  "enablement_reason": "Detailed explanation (if true or uncertain).",
  "weak_dataflow": [true/false],
  "weak_enablement": [true/false]
}

# Notes  
- Differentiate persistent data vs. ephemeral state.
- Count enablement only if direct precondition within same session/tab/context.
- Use 'weak_*' for borderline cases.
"""
PHASE_1_PROMPT_TEMPLATE = """
Decide whether the relationship between A and B exhibits:  
1. **Dataflow**: A writes or persists data that B reads or loads within the same resource or context.  
2. **Enablement**: A directly enables B's precondition to run or execute within the same session, tab, or context.

# Steps  

1. **Understand Context**: Analyze the scenario where A interacts with B to identify how A influences B.  
2. **Dataflow Analysis**:  
   - Confirm if A produces or modifies data (e.g., storage, database, file, buffer) that B subsequently accesses.  
   - Verify that both A and B operate within the same resource or context for data persistence.  
3. **Enablement Analysis**:  
   - Determine whether A directly triggers, fulfills, or initiates conditions required for B's execution.  
   - Ensure this enablement occurs in the same session, tab, or context.  
4. **Evaluate Results**:  
   - **"Dataflow only"**: If A creates or modifies data that B accesses without fulfilling preconditions.  
   - **"Enablement only"**: If A meets preconditions for B without involving data persistence.  
   - **"Both Dataflow and Enablement"**: If both conditions are satisfied.  
   - **"Neither"**: If neither condition is satisfied.

# Output Format  

Provide the results as JSON formatted as follows:  

```json
{
  "dataflow": [true/false],
  "enablement": [true/false],
  "confidence_dataflow": [0-1 range],
  "confidence_enablement": [0-1 range],
  "dataflow_reason": "Detailed explanation of the dataflow relationship (if true).",
  "enablement_reason": "Detailed explanation of the enablement relationship (if true).",
  "weak_dataflow": [true/false],
  "weak_enablement": [true/false]
}
```

# Notes  

- **Data Persistence**: Differentiate persistent interactions (e.g., file, database) from temporary state changes or ephemeral variables.  
- **Direct Influence**: Ensure enablement involves direct influence from A to B within the same context; do not count indirect functionalities.  
- **Weak Relationships**: Use `weak_dataflow` or `weak_enablement` for cases where relationships are present but do not fully meet the criteria of strong interaction.  
- Include placeholders for context-specific examples upon request.
"""
PHASE_1_PROMPT_TEMPLATE = """Decide whether the relationship from **A → B** exhibits:

1. **Dataflow**: A writes, produces, or persists **explicit data** (e.g., file, buffer, object, value, or any form of structured data) that **B subsequently reads, loads, or depends on** within the same resource or context.
   - **Dataflow is not applicable if A only modifies internal state or environmental context (e.g., browser history state) without producing actual data that can be read or consumed by B.**

2. **Enablement**: A **directly triggers** or **satisfies preconditions** required for **B's execution** within the same session, tab, or context. 
   - For **enablement**, A must be a **necessary condition** for B to execute, not just a possible or optional control of execution order.
   - **Timing controls** (e.g., delays, wait actions) should not be treated as enablement. They facilitate the possibility of success but do not directly trigger B's execution.

--- 

# STRICT DIRECTION RULE
- The relationship direction is **A → B only**.  
- Always reason in this order: Does A affect B? Never the reverse.  
- If evidence shows the reverse direction (B → A), explicitly note that and set `dataflow=false` and `enablement=false`.

---

# Step-by-Step Reasoning

1. **Direction Check**  
   - Rephrase the question as: “Does A’s behavior produce outputs or conditions that B later consumes or relies on?”  
   - If B produces outputs that A uses, mark this as **no dataflow or enablement from A → B**.

2. **Dataflow Analysis**  
   - Confirm A produces or modifies **explicit data** (file, buffer, snapshot, object, state) that B reads, loads, or depends on.  
   - The data must be **explicitly produced** by A and **directly consumed** by B. 
   - **Do not count B → A dependencies** or situations where B simply operates on a resource that is not directly influenced by A.

3. **Enablement Analysis**  
   - Does A **directly trigger or create the necessary conditions** for B to execute? 
   - If A’s action is **essential** for B to execute, then A is an enablement trigger. If not, then A is only influencing **execution order**, which **does not count** as enablement. 
   - The enablement must occur within the **same session, tab, or context**.

4. **Evaluation**  
   - "Dataflow only": A writes/persists data that B reads (A → B).  
   - "Enablement only": A directly fulfills conditions or triggers B’s execution without involving data persistence. (A → B).  
   - "Both": A’s output both feeds and enables B.  
   - "Neither": No directional influence from A → B.

---

# Output Format

```json
{
  "dataflow": [true/false],
  "enablement": [true/false],
  "confidence_dataflow": [0-1],
  "confidence_enablement": [0-1],
  "dataflow_reason": "Explain directionally: how A’s output feeds B, or why not.",
  "enablement_reason": "Explain directionally: how A enables B, or why not."
}

# Notes  

- **Confidence Values**: Confidence levels should quantify the degree of certainty for dataflow and enablement determinations, based on the given context or descriptions (range: 0–1).
- **Resource/Context Constraint**: Ensure the interaction happens strictly within the same resource, session, or context for dataflow or enablement to apply. 
- **Enablement Restriction**: Enablement only applies when A is a **necessary condition** for B’s execution, not just a potential sequence controller.
"""
# --- 3. Tool Loading ---

def load_tools_from_server(server_path: Path) -> List[dict]:
    """
    Load tools and their summaries from an mcp server.
    Expected directory: {server}/results_phase1/*_candidates.json contains phase0.functional_summary
    """
    tools = []
    data_dir = server_path / "results_phase1"
    if not data_dir.is_dir():
        logging.warning(f"Directory 'results_phase1' not found in {server_path}. Skipping.")
        return []

    for json_file in data_dir.glob("*_candidates.json"):
        try:
            tool_name = json_file.name.replace("_candidates.json", "")
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            summary = data["phase0"]["functional_summary"]
            tools.append({
                "tool_name": tool_name,
                "functional_summary": summary
            })
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logging.error(f"Failed to load or parse {json_file}: {e}")

    return tools

# --- 4. Response Parsing and Normalization ---

def _strip_code_fences(s: str) -> str:
    """
    Remove ```json ... ``` or ``` ... ``` wrapping; strip extra '###END###' and whitespace.
    """
    if s is None:
        return ""
    s = s.strip()
    # Remove triple backtick fences
    if s.startswith("```"):
        # Find the first line language hint
        first_nl = s.find("\n")
        if first_nl != -1:
            maybe_lang = s[3:first_nl].lower().strip(" \r\t`")
            if maybe_lang in ("json", ""):
                s = s[first_nl+1:]
        # Remove trailing ```
        if s.endswith("```"):
            s = s[:-3]
    # Remove common trailing markers
    s = s.replace("###END###", "").strip()
    return s

def _safe_json_loads(content: str) -> dict:
    """
    Try to parse the returned JSON string, handling common wrapping/redundancy issues.
    """
    raw = _strip_code_fences(content)
    # Sometimes the model adds an extra '}' or misses a comma; attempt minimal invasive fixes
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise

def _normalize_edge_result(producer: dict, consumer: dict, result_json: dict) -> Optional[Dict[str, Any]]:
    """
    Target unified structure:
      {
        producer, consumer,
        dataflow: bool, enablement: bool,
        confidence_dataflow: float|None,
        confidence_enablement: float|None,
        dataflow_reason: str,
        enablement_reason: str,
        weak_dataflow: bool|None,
        weak_enablement: bool|None
      }
    """
    # Expected new JSON schema (flat keys)
    df = bool(result_json.get("dataflow", False))
    en = bool(result_json.get("enablement", False))
    edge = {
        "producer": producer["tool_name"],
        "consumer": consumer["tool_name"],
        "dataflow": df,
        "enablement": en,
        "confidence_dataflow": result_json.get("confidence_dataflow"),
        "confidence_enablement": result_json.get("confidence_enablement"),
        "dataflow_reason": result_json.get("dataflow_reason", ""),
        "enablement_reason": result_json.get("enablement_reason", ""),
    }
    return edge

# --- 5. LLM Call (with retry) ---

# Thread-local client to avoid sharing connections across threads
_thread_local = threading.local()

def _get_client() -> OpenAI:
    client = getattr(_thread_local, "client", None)
    if client is None:
        #timeout = httpx.Timeout(600.0, connect=60.0)  # 600-second total timeout and 60-second connection timeout.
        _thread_local.client = OpenAI(
            base_url=ENDPOINT,
            api_key=API_KEY,
        )
        client = _thread_local.client
    return client

def analyze_link_once(producer: dict, consumer: dict) -> Dict[str, Any]:
    """
    Single LLM call to analyze whether dataflow/enablement exists between a pair of tools.
    Only raises exceptions, no retry; retry is handled by the upper layer.
    """
    # Sleep 10 seconds before each API call
    time.sleep(10)
    
    client = _get_client()
    user_payload = {
        "A": {"tool_name": producer["tool_name"], "functional_summary": producer["functional_summary"]},
        "B": {"tool_name": consumer["tool_name"], "functional_summary": consumer["functional_summary"]},
    }
    user_prompt = "USER INPUT:\n" + json.dumps(user_payload, ensure_ascii=False, indent=2)
    resp = client.chat.completions.create(
        extra_headers={
            "HTTP-Referer": "",  # Optional. Site URL for rankings on openrouter.ai.
            "X-Title": "",  # Optional. Site title for rankings on openrouter.ai.
        },
        extra_body={"reasoning":{"effort":"high"}},
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": PHASE_1_PROMPT_TEMPLATE},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.0,
        max_tokens=8096,
    )
    msg = resp.choices[0].message
    parsed = _safe_json_loads(msg.content)
    return parsed

def analyze_link_with_retry(producer: dict, consumer: dict) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Call with retry, returns (edge_dict | None, error | None).
    """
    delay = 1.0
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result_json = analyze_link_once(producer, consumer)
            edge = _normalize_edge_result(producer, consumer, result_json)
            return edge, None
        except Exception as e:
            last_err = f"attempt={attempt} error={repr(e)}"
            time.sleep(delay)
            delay *= RETRY_BACKOFF
    return None, last_err

# --- 6. Thread-safe writing (immediate write per entry) ---

class EdgeWriters:
    def __init__(self, server_dir: Path):
        self.ok_path = server_dir / "_phase1_edges.jsonl"
        self.no_path = server_dir / "_phase1_not_edges.jsonl"
        self.err_path = server_dir / "_phase1_errors.jsonl"
        self._lock_ok = threading.Lock()
        self._lock_no = threading.Lock()
        self._lock_err = threading.Lock()
        # Create empty files if they don't exist
        for p in (self.ok_path, self.no_path, self.err_path):
            if not p.exists():
                p.touch()

    def write_ok(self, obj: dict):
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock_ok:
            with open(self.ok_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def write_no(self, obj: dict):
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock_no:
            with open(self.no_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def write_err(self, obj: dict):
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock_err:
            with open(self.err_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

# --- 7. Process single server (multithreaded) ---

def is_server_already_processed(server_path: Path, expected_pairs_count: int) -> bool:
    """
    Check if a server has already been processed by counting entries in output files.
    Returns True if all pairs have been processed.
    """
    edges_file = server_path / "_phase1_edges.jsonl"
    not_edges_file = server_path / "_phase1_not_edges.jsonl"
    
    processed_count = 0
    
    # Count entries in edges file
    if edges_file.exists():
        try:
            with open(edges_file, "r", encoding="utf-8") as f:
                processed_count += sum(1 for line in f if line.strip())
        except (OSError, IOError):
            pass
    
    # Count entries in not_edges file
    if not_edges_file.exists():
        try:
            with open(not_edges_file, "r", encoding="utf-8") as f:
                processed_count += sum(1 for line in f if line.strip())
        except (OSError, IOError):
            pass
    
    # If processed count matches expected pairs, server is already processed
    return processed_count >= expected_pairs_count

def process_server(server_path: Path) -> dict:
    tools = load_tools_from_server(server_path)
    if len(tools) < 2:
        return {"server": server_path.name, "status": "skipped", "links_found": 0}

    all_pairs = list(itertools.permutations(tools, 2))
    expected_pairs_count = len(all_pairs)
    
    # Check if already processed
    if is_server_already_processed(server_path, expected_pairs_count):
        logging.info(f"Server {server_path.name} already processed ({expected_pairs_count} pairs), skipping...")
        # Count existing links for summary
        edges_jsonl = server_path / "_phase1_edges.jsonl"
        discovered_count = 0
        if edges_jsonl.exists():
            try:
                with open(edges_jsonl, "r", encoding="utf-8") as f:
                    discovered_count = sum(1 for line in f if line.strip())
            except (OSError, IOError):
                pass
        return {
            "server": server_path.name,
            "status": "already_processed",
            "links_found": discovered_count
        }
    
    writers = EdgeWriters(server_path)

    discovered_count = 0
    futures = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for producer, consumer in all_pairs:
            futures.append(
                ex.submit(analyze_link_with_retry, producer, consumer)
            )

        for fut in tqdm(as_completed(futures), total=len(futures), desc=f"Processing {server_path.name}", leave=False):
            edge, err = fut.result()
            if err is not None and edge is None:
                # Log error
                writers.write_err({"error": err})
                continue
            if edge is None:
                # Edge case: neither err nor edge (unlikely), add protection
                writers.write_err({"error": "edge=None without explicit error"})
                continue

            if edge.get("dataflow") or edge.get("enablement"):
                writers.write_ok(edge)
                discovered_count += 1
            else:
                writers.write_no(edge)

    # After completion, aggregate JSONL -> JSON (maintain compatibility with original output for subsequent scripts)
    ok_json = _collect_jsonl(server_path / "_phase1_edges.jsonl")
    no_json = _collect_jsonl(server_path / "_phase1_not_edges.jsonl")

    try:
        with open(server_path / "_phase1_discovered_edges.json", "w", encoding="utf-8") as f:
            json.dump(ok_json, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logging.error(f"Failed to write {server_path / '_phase1_discovered_edges.json'}: {e}")

    try:
        with open(server_path / "_phase1_not_edges.json", "w", encoding="utf-8") as f:
            json.dump(no_json, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logging.error(f"Failed to write {server_path / '_phase1_not_edges.json'}: {e}")

    return {
        "server": server_path.name,
        "status": "completed",
        "links_found": discovered_count,
    }

def _collect_jsonl(path: Path) -> List[dict]:
    out = []
    if not path.exists():
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    # Fallback: skip bad lines
                    pass
    except OSError:
        pass
    return out

# --- 8. Load Server Directories from Groups File ---

def load_server_dirs_from_groups(groups_file: Path, group_index: int) -> List[Path]:
    """
    Load groups JSON (array of {group_index, paths}) and collect
    the server directory paths from the specified group.
    """
    try:
        with groups_file.open("r", encoding="utf-8") as f:
            groups = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read groups file {groups_file}: {e}")
        return []

    selected_paths: List[str] = []
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, dict) and g.get("group_index") == group_index:
                selected_paths = [p for p in g.get("paths", []) if isinstance(p, str)]
                break
    else:
        logging.error("Groups file format unexpected: expected a list of groups")
        return []

    server_dirs: List[Path] = []
    for repo_path_str in selected_paths:
        server_dir = Path(repo_path_str)
        if server_dir.exists() and server_dir.is_dir():
            server_dirs.append(server_dir)
        else:
            logging.warning(f"Server directory does not exist: {server_dir}")
    return server_dirs

# --- 9. Main Process ---

def main():
    parser = argparse.ArgumentParser(description="Run MCP edge detection analysis")
    parser.add_argument("--groups-file", type=str, default=None, help="Path to groups.json (from group_projects.py)")
    parser.add_argument("--group-index", type=int, default=None, help="Group index to run from groups file")
    args = parser.parse_args()

    if not API_KEY:
        logging.error("OPENROUTER_API_KEY or OPENAI_API_KEY environment variable not set.")
        return

    # Determine server directory list
    server_dirs: List[Path] = []
    
    if args.groups_file and args.group_index is not None:
        # Load from groups file
        groups_file = Path(args.groups_file)
        if not groups_file.exists():
            logging.error(f"Groups file '{groups_file}' does not exist.")
            return
        server_dirs = load_server_dirs_from_groups(groups_file, args.group_index)
        logging.info(f"Loaded {len(server_dirs)} server directories from groups file (group_index={args.group_index}).")
    else:
        # Use default directory as fallback
        try:
            server_dirs = [d for d in DEFAULT_ROOT_DIR.iterdir() if d.is_dir()]
            logging.info(f"Found {len(server_dirs)} mcp server directories in default directory '{DEFAULT_ROOT_DIR}'.")
        except FileNotFoundError:
            logging.error(f"Default root directory '{DEFAULT_ROOT_DIR}' does not exist.")
            return

    if not server_dirs:
        logging.warning("No server directories found. Please check input parameters.")
        return

    results_summary = []
    # Use multithreading to process multiple servers in parallel
    # Use smaller thread count to avoid resource contention, as each server already uses multithreading internally
    server_workers = min(len(server_dirs), max(2, MAX_WORKERS // 2))
    with ThreadPoolExecutor(max_workers=server_workers) as server_executor:
        # Submit all server processing tasks
        server_futures = {
            server_executor.submit(process_server, server_dir): server_dir
            for server_dir in server_dirs
        }
        
        # Use tqdm to display overall progress
        for fut in tqdm(as_completed(server_futures), total=len(server_futures), desc="Overall progress"):
            server_dir = server_futures[fut]
            try:
                summary = fut.result()
                results_summary.append(summary)
            except Exception as e:
                logging.error(f"Error processing {server_dir.name}: {e}")
                results_summary.append({
                    "server": server_dir.name,
                    "status": "error",
                    "error": str(e),
                    "links_found": 0
                })

    total_links = sum(r.get("links_found", 0) for r in results_summary if r.get("status") in ("completed", "already_processed"))
    completed_count = sum(1 for r in results_summary if r.get("status") == "completed")
    already_processed_count = sum(1 for r in results_summary if r.get("status") == "already_processed")
    skipped_count = sum(1 for r in results_summary if r.get("status") == "skipped")
    error_count = sum(1 for r in results_summary if r.get("status") == "error")
    
    print("\n--- Phase 1 Complete (Concurrent Version) ---")
    print(f"  Total servers: {len(results_summary)}")
    print(f"  Newly processed: {completed_count}")
    print(f"  Already processed (skipped): {already_processed_count}")
    print(f"  Skipped (insufficient tools): {skipped_count}")
    print(f"  Errors: {error_count}")
    print(f"  Total links found (Edges): {total_links}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
