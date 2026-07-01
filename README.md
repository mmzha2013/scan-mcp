# MCP Research Pipeline

This repository contains a static-analysis and LLM-assisted pipeline for analyzing MCP server repositories. The pipeline extracts MCP tool names, resolves tool handlers, builds intra-tool call chains, compacts tool code, and then runs single-tool and multi-tool vulnerability analysis.

Demo projects and sample inputs are stored in the `demos/` folder. If this checkout does not include that folder yet, create it at the repository root and place the demo MCP servers there. For a quick test, copy one demo server into `mcp_servers_repos/` and run the pipeline on that small input before scaling to a large corpus.

## 0. Video Demos

We provide video demos with the supplementary materials. Reviewers can download the video files and watch them locally.

The demos illustrate how to prepare example MCP server inputs, run the pipeline, and inspect the generated analysis outputs. The corresponding demo projects and sample inputs are stored in the `demos/` folder. If this checkout does not include that folder yet, create it at the repository root and place the demo MCP servers there.


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
python -m pip install `
  openai==2.6.1 `
  requests==2.32.5 `
  httpx==0.28.1 `
  tqdm==4.67.1 `
  networkx==3.5 `
  langgraph==1.2.7 `
  langgraph-checkpoint==4.1.1 `
  langgraph-prebuilt==1.1.0 `
  langgraph-sdk==0.4.2 `
  langchain-core==1.4.8 `
  tree-sitter==0.25.2 `
  tree-sitter-python==0.25.0 `
  tree-sitter-go==0.25.0 `
  tree-sitter-php==0.24.1 `
  tree-sitter-java==0.23.5 `
  tree-sitter-c-sharp==0.23.1 `
  tree-sitter-javascript==0.25.0 `
  tree-sitter-typescript==0.23.2 `
  tree-sitter-kotlin==1.1.0 `
  tree-sitter-ruby==0.23.1 `
  tree-sitter-rust==0.24.0 `
  tree-sitter-swift==0.0.1
```

If your network has trouble reaching PyPI, configure a mirror and then rerun the install command above:

```powershell
python -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
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

Several scripts call an OpenAI-compatible chat-completions endpoint. For Azure/OpenAI-compatible usage, set these variables in PowerShell:

```powershell
$env:AZURE_API_KEY="<your-api-key>"
$env:OPENAI_API_KEY=$env:AZURE_API_KEY
$env:OPENAI_API_BASE="https://mzha-0007-resource.services.ai.azure.com/openai/v1"
$env:OPENAI_MODEL="grok-4-1-fast-reasoning"
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

```powershell
cd D:\mac\Workspace\Workspace\B657\MCP_research
```

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

For demo runs, use the `demos/` folder:

```powershell
New-Item -ItemType Directory -Force .\mcp_servers_repos
Copy-Item -Recurse .\demos\<demo-server-folder> .\mcp_servers_repos\
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
python .\scripts\6_tool_chains_candidate_pairs_2.py --groups-file groups.json --group-index 0
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
