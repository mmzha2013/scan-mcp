#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 2 pure fine-grained path finding. It does not depend on Phase-0 role files or concrete tool names; it uses source and sink annotations to keep potentially exploitable chains."""

import json
import os
import sys
from pathlib import Path
from tqdm import tqdm
import networkx as nx

# ====== Configuration ======
MAX_CHAIN_LENGTH = 3
# ===================

# 1. Untrusted entrypoint types.
UNTRUSTED_SOURCE_TYPES = {
    "user_input",
    "http_request_param",
    "http_header",
    "cookie_value",
    "form_field",
    "file_upload",
    "path_param",
    "ws_message",
    "email_input",
    "webhook_callback",
    "oauth_callback",
    "api_response_parse",
    "external_url_response",
    "cli_arg_read",
}

# 2. Sinks that can cause real server or resource impact.
SERVER_IMPACT_SINK_TYPES = {
    # Process, command, and permission sinks.
    "exec_shell",
    "process_spawn",
    "process_kill",
    "dynamic_code_exec",
    "command_injection",
    "privilege_escalation",
    "sandbox_escape",
    "plugin_load",
    "dynamic_import",
    "dependency_download",
    # File, storage, and configuration sinks.
    "fs_write",
    "fs_delete",
    "fs_rename",
    "archive_extract",
    "symlink_create",
    "path_traversal",
    "storage_object_write",
    "cloud_api_access",
    "env_write",
    "secret_write",
    "chmod_chown",
    "systemd_unit_create",
    "cron_create",
    "shared_state_modify",
    "keystore_access",
    # Data exfiltration and network side-channel sinks.
    "outbound_upload",
    "dns_exfil",
    "data_export",
    "socket_connect",
    "ws_send",
    "email_send",
    "notification_send",
    # LLM system-message sinks.
    "system_message_write",
}

# 3. Network sinks handled separately for the rule that only outbound paths require a controllable entry.
NETWORK_ONLY_SINKS = {
    "outbound_request",
    "open_redirect",
    "socket_connect",
    "ws_send",
    "dns_exfil",
    "outbound_upload",
}


def load_json_maybe_double(path: Path):
    """Load JSON, including files that contain a JSON-encoded string."""
    text = path.read_text(encoding="utf-8")
    obj = json.loads(text)
    if isinstance(obj, str):
        obj = json.loads(obj)
    return obj


def load_fine_dir(dirpath: Path) -> dict:
    """Load fine-grained source and sink annotation files from a directory."""
    res = {}
    if not dirpath.exists():
        return res
    for f in dirpath.glob("*.json"):
        try:
            data = load_json_maybe_double(f)
        except Exception:
            continue
        name = data.get("tool_name")
        if not name:
            continue
        res[name] = {
            "sources": data.get("sources", []),
            "sinks": data.get("sinks", []),
        }
        if len(res[name]["sources"]) == 0:
            res[name]["sources"] = [{"type": "user_input", "snippet_evidence": ""}]
    return res


def getCandidateToolChains(source_sink_dir, edges_file,output_file):
    print("--- Phase 2: fine-grained path finding (types only) ---")

    # 1) Load fine-grained annotations.
    fine_roles = load_fine_dir(source_sink_dir)
    print(f"[info] loaded fine-grained tool annotations: {len(fine_roles)}")

    # 2) Load edges.
    try:
        links = load_json_maybe_double(edges_file)
    except Exception as e:
        print(f"[error] cannot read edges: {e}", file=sys.stderr)
        return

    # 3) Build the graph.
    G = nx.DiGraph()
    all_nodes = set()
    edge_conf = {}

    for link in links:
        prod = link.get("producer")
        cons = link.get("consumer")
        if not prod or not cons:
            continue

        dataflow = link.get("dataflow", False)
        enablement = link.get("enablement", False)
        cd = link.get("confidence_dataflow", 0.0)
        ce = link.get("confidence_enablement", 0.0)

        G.add_edge(
            prod,
            cons,
            dataflow=dataflow,
            enablement=enablement,
            confidence_dataflow=cd,
            confidence_enablement=ce,
        )
        all_nodes.add(prod)
        all_nodes.add(cons)
        edge_conf[(prod, cons)] = {"cd": cd, "ce": ce}

    # 4) Determine source and sink nodes from fine-grained annotations.
    # Source: any untrusted input type.
    valid_sources = set()
    for node in all_nodes:
        info = fine_roles.get(node)
        if not info:
            continue
        src_types = {s.get("type") for s in info.get("sources", []) if s.get("type")}
        if src_types & UNTRUSTED_SOURCE_TYPES:
            valid_sources.add(node)

    # Sink: server-impact sinks or network sinks.
    valid_sinks = set()
    for node in all_nodes:
        info = fine_roles.get(node)
        if not info:
            continue
        sink_types = {s.get("type") for s in info.get("sinks", []) if s.get("type")}
        # Real server impact.
        if sink_types & SERVER_IMPACT_SINK_TYPES:
            valid_sinks.add(node)
            continue
        # Keep network-only cases initially and filter them more carefully later.
        if sink_types & NETWORK_ONLY_SINKS:
            valid_sinks.add(node)

    print(f"[info] fine sources: {len(valid_sources)}, fine sinks: {len(valid_sinks)}")

    if not valid_sources or not valid_sinks:
        print("[warn] no valid sources or sinks, exit.")
        return

    # 5) Find paths and apply smart filters.
    kept_chains = []
    total_paths = 0

    for src in tqdm(valid_sources, desc="paths from sources"):
        try:
            paths_iter = nx.all_simple_paths(G, source=src, target=valid_sinks, cutoff=MAX_CHAIN_LENGTH)
        except nx.NodeNotFound:
            continue

        for path in paths_iter:
            total_paths += 1

            # Filter 1: require at least one dataflow edge.
            has_df = False
            for i in range(len(path) - 1):
                e = G.get_edge_data(path[i], path[i+1])
                if e and e.get("dataflow"):
                    has_df = True
                    break
            if not has_df:
                continue

            # Collect all sink types found along the path.
            path_sink_types = set()
            path_has_server_impact = False
            path_has_only_network = True  # Assume network-only until a server-impact sink is found.

            for node in path:
                info = fine_roles.get(node)
                if not info:
                    continue
                node_sink_types = {s.get("type") for s in info.get("sinks", []) if s.get("type")}
                if not node_sink_types:
                    continue
                path_sink_types |= node_sink_types
                # Whether the path contains real server impact.
                if node_sink_types & SERVER_IMPACT_SINK_TYPES:
                    path_has_server_impact = True
                    path_has_only_network = False
                else:
                    # A sink outside the network set means this is not network-only.
                    if not node_sink_types.issubset(NETWORK_ONLY_SINKS):
                        path_has_only_network = False

            # Filter 2: keep paths that contain a real server-impact sink.
            if path_has_server_impact:
                pass
            else:
                # Without server impact, check whether the path is network-only.
                if path_sink_types and path_sink_types.issubset(NETWORK_ONLY_SINKS):
                    # Network-only paths are kept only because the entry node was already selected as untrusted.
                    pass
                else:
                    # Drop paths with no sink or only unknown sinks.
                    continue

            # Compute average confidence.
            steps = len(path) - 1 if len(path) > 1 else 1
            df_sum = 0.0
            en_sum = 0.0
            for i in range(len(path) - 1):
                conf = edge_conf.get((path[i], path[i+1]), {"cd": 0.0, "ce": 0.0})
                df_sum += conf["cd"]
                en_sum += conf["ce"]
            avg_df = df_sum / steps
            avg_en = en_sum / steps

            # Attach fine-grained annotation details.
            nodes_detail = []
            for node in path:
                nodes_detail.append({
                    "tool": node,
                    "sources": fine_roles.get(node, {}).get("sources", []),
                    "sinks": fine_roles.get(node, {}).get("sinks", []),
                })

            kept_chains.append({
                "chain": path,
                "nodes": nodes_detail,
                "confidence": {
                    "dataflow_confidence": avg_df,
                    "enablement_confidence": avg_en
                }
            })

    # 6) Sort and save.
    kept_chains.sort(
        key=lambda x: (x["confidence"]["dataflow_confidence"] + x["confidence"]["enablement_confidence"]),
        reverse=True
    )

    print(f"[result] total theoretical paths: {total_paths}")
    print(f"[result] kept after fine-grained filter: {len(kept_chains)}")

    try:
        output_file.write_text(json.dumps(kept_chains, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[ok] written to {output_file}")
    except IOError as e:
        print(f"[error] cannot write output: {e}", file=sys.stderr)

def main():
    baseDir = '../mcp_servers_repos'
    projects = os.listdir(baseDir)
    #projects = projects[:50]
    for project in projects:
        source_sink_dir = Path(baseDir+'/'+project+'/output_phase_source_sink1')
        edges_file = Path(baseDir+'/'+project+'/_phase1_discovered_edges.json')
        output_file = Path(baseDir+'/'+project+'/_phase1_vulnerable_chains.json')

        if not edges_file.exists():
            edges_file = Path(baseDir + '/' + project + '/_phase1_discovered_edges.json')
            if not edges_file.exists():
                print(project)
                continue

        getCandidateToolChains(source_sink_dir, edges_file, output_file)

if __name__ == "__main__":
    main()
