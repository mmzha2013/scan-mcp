# SCAN-MCP Research Pipeline

This anonymous artifact contains a static-analysis and LLM-assisted pipeline for analyzing MCP server repositories. The pipeline extracts MCP tool names, resolves tool handlers, builds intra-tool call chains, compacts tool code, and runs single-tool and multi-tool vulnerability analysis.

The artifact includes sample inputs and sandbox demonstration materials under `demos/`. For a quick availability check, reviewers can inspect the included demo materials and run the pipeline on a small copied input under `mcp_servers_repos/` before scaling to a larger corpus. Additional MCP server repositories can be placed under `mcp_servers_repos/` using the directory layout described below.

## Review-Only Notice

This anonymous artifact is provided solely for review, verification, and replication of the accompanying double-anonymous submission. Program committee members and reviewers may inspect, execute, and evaluate the artifact for review purposes.

The code, dataset metadata, prompts, proof-of-concept materials, and demonstration videos are not yet released for public distribution, reuse, redistribution, mirroring, or derivative use outside the review process. No license for broader use is granted at this stage.

## Ethical and Responsible Use Disclaimer

This artifact is intended strictly for academic, educational, and defensive security research. The pipeline analyzes MCP server repositories and may include security-evaluation materials, vulnerability candidates, proof-of-concept inputs, and sandbox demonstration videos.

Do not deploy these tools, prompts, or proof-of-concept materials against production systems, unauthorized environments, live third-party services, or infrastructure that you do not own or have explicit permission to test. All evaluations should be confined to isolated, legally authorized, and locally controlled sandbox environments.

The artifact is designed for offline analysis of repository snapshots. It does not require probing live MCP deployments. Users are responsible for ensuring that any use of this artifact complies with applicable laws, policies, and ethical security-research practices.

## 0. Video Demos

The `demos/` folder includes three sandbox demonstration videos corresponding to the case studies in the paper:

1. Arbitrary command execution.
2. Write-and-execute tool-chain vulnerability.
3. Browse-click-upload tool-chain vulnerability.

These videos demonstrate the confirmed behaviors in isolated sandbox environments and do not require probing live deployments.

## 1. Create a Conda Environment

Use Python 3.11 for the cleanest dependency compatibility.

```powershell
conda create -n mcp-test python=3.11 pip -y
conda activate mcp-test
python -m pip install --upgrade pip
```

## 2. Install Python Dependencies

Install the runtime packages required by the pipeline scripts.

```powershell
python -m pip install -r requirements.txt
```

## 3. Verify the Environment

Run this import check before starting the pipeline.

```powershell
python -c "import openai, requests, httpx, tqdm, networkx, langgraph, tree_sitter; import tree_sitter_python, tree_sitter_go, tree_sitter_php, tree_sitter_java, tree_sitter_c_sharp, tree_sitter_javascript, tree_sitter_typescript, tree_sitter_kotlin, tree_sitter_ruby, tree_sitter_rust, tree_sitter_swift; print('ok')"
```

Expected output:

```text
ok
```

## 4. Configure LLM Credentials

Inspecting the artifact and watching the sandbox demonstration videos does not require any API credentials. Re-running the LLM-assisted analysis steps requires access to an OpenAI-compatible chat-completions endpoint.

For Azure/OpenAI-compatible usage, set these variables in PowerShell:

```powershell
$env:AZURE_API_KEY="<your-api-key>"
$env:OPENAI_API_KEY=$env:AZURE_API_KEY
$env:OPENAI_API_BASE="<your-endpoint-url>"
$env:OPENAI_MODEL="<model-name>"
```

Some legacy scripts use older variable names. Set these as aliases if you want them to use the same endpoint and model:

```powershell
$env:DASHSCOPE_API_KEY=$env:AZURE_API_KEY
$env:OPENAI_BASE_URL=$env:OPENAI_API_BASE
$env:LLM_MODEL_ANALYZE=$env:OPENAI_MODEL
$env:LLM_MODEL_RESOLVE=$env:OPENAI_MODEL
$env:LLM_MODEL_VERIFY=$env:OPENAI_MODEL
```

Before running the phase-6 scripts, also check whether the script itself contains hardcoded `base_url`, `api_key`, or `model` values. Update them if they do not match your endpoint.

## 5. Prepare Input Repositories

Run all commands from the repository root, not from the `scripts/` directory.

Place MCP server repositories under `mcp_servers_repos/`:

```text
mcp_servers_repos/
  server_a/
    README.md
    package.json
    src/...
  server_b/
    README.md
    pyproject.toml
    ...
```

## 6. Run the Pipeline

### Step 1: Extract Tool Names

```powershell
python .\scripts\1_tool_name_extraction.py
```

Output per server:

```text
mcp_servers_repos/<server>/tool_extraction_results.json
```

Important: the handler-extraction stage expects each server to have `grep_tool_extraction.json`. If your current tool-name extractor produces `tool_extraction_results.json`, export or convert the discovered tool list to the `grep_tool_extraction.json` format before Step 2. Many prepared demo/sample folders already include this file.

### Step 2: Extract Tool Handlers

```powershell
python .\scripts\2_extract_tool_handler.py
```

Expected input per server:

```text
mcp_servers_repos/<server>/grep_tool_extraction.json
```

Output per server:

```text
mcp_servers_repos/<server>/output_refined_v1/*.json
```

### Step 3: Analyze Call Chains

```powershell
python .\scripts\3_analyze_call_chains.py
```

Output per server:

```text
mcp_servers_repos/<server>/call_chains.json
```

### Step 4: Extract Compact Tool Code

```powershell
python .\scripts\4_extract_tool_codes.py
```

Output per server:

```text
mcp_servers_repos/<server>/tool_codes_compact_v1.json
mcp_servers_repos/<server>/tool_codes_compact_v1.txt
```

### Step 5: Analyze Single-Tool Vulnerabilities

```powershell
python .\scripts\5_single_tool_vulnerabilities.py
```

Typical output per server:

```text
mcp_servers_repos/<server>/results_phase1_no_slicing/
```

### Step 6: Extract Tool Source/Sink Roles

```powershell
python .\scripts\6__tool_chains_source_sink_1.py
```

Output per server:

```text
mcp_servers_repos/<server>/output_phase_source_sink1/*.json
```

### Step 7: Generate Candidate Tool Pairs

```powershell
python .\scripts\6_tool_chains_candidate_pairs_2.py
```

This script can also run by group if you provide a groups file:

```powershell
python .\scripts\6_tool_chains_candidate_pairs_2.py
```

Typical outputs:

```text
_phase1_discovered_edges.json
_phase1_not_edges.json
_phase1_errors.jsonl
```

### Step 8: Build Candidate Tool Chains

```powershell
python .\scripts\6__tool_chains_candidate_tool_chains_3.py
```

Typical output:

```text
_phase1_vulnerable_chains.json
```

### Step 9: Validate Multi-Tool Vulnerabilities

```powershell
python .\scripts\6_tool_chains_vulnerabilities_4.py
```

Output per server:

```text
mcp_servers_repos/<server>/output_phase_6_llm/*.json
```

## 7. Troubleshooting

If `ModuleNotFoundError: tree_sitter_*` appears, install the corresponding `tree-sitter-*` package listed in Step 2.

If `networkx==3.5` fails to install, you are probably using Python 3.10 or older. Either recreate the environment with Python 3.11 or use `networkx==3.4.2`.

If a script finds no projects, make sure you are running from the repository root and that input servers are under `mcp_servers_repos/`.

If an LLM call returns 400, 401, or 404, check the endpoint, API key, model name, and whether the script is using environment variables or hardcoded API settings.
