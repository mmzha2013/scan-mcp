#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MCP Tool Handler Extractor - Refined (Two-Step Logic)
----------------------------------------------------------------------------
-
- **Step 1: Analyze & Plan (LLM)**
-   Analyzes tool registration, determines handler type (inline vs. identifier),
-   and creates a resolution plan by inspecting imports.
-
- **Step 2: Resolve & Verify (Local Logic + Optional LLM)**
-   If handler is inline, proceeds directly to local verification.
-   If handler is an identifier, uses the plan to gather cross-file context
-   for a targeted LLM call, followed by local verification.
-
- This approach reduces LLM calls from 3-4 to 1-2, simplifying the logic
- while retaining multi-language support and robust, verbatim code extraction.
"""

import os
import re
import json
import sys
from pathlib import Path
from string import Template
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ProcessPoolExecutor, as_completed

from openai import OpenAI  # pip install openai

# =================== CONFIG ===================

API_KEY = os.environ.get("OPENAI_API_KEY", "sk-or-v1-xxx")
BASE_URL = os.environ.get("OPENAI_API_BASE", "https://openrouter.ai/api/v1")

CODE_DIR = Path("../mcp_servers_repos")

# We can use the same powerful model for both stages
MODEL_ANALYZE = os.environ.get("LLM_MODEL_ANALYZE", "qwen/qwen3-coder")
MODEL_RESOLVE = os.environ.get("LLM_MODEL_RESOLVE", "qwen/qwen3-coder")
MODEL_VERIFY = os.environ.get("LLM_MODEL_VERIFY", "qwen/qwen3-coder")  # For final selection

POLL_TIMEOUT_SEC = 1200
MAX_CANDIDATE_FILES_PER_TOOL = 30
MAX_FILE_BYTES_PER_PROMPT = 350_000
WINDOW_LINES = 20

IGNORE_DIRS = {"docs", "tests", ".venv", "build", ".github", "npm", "node_modules", ".git", "dist", "__pycache__",
               ".cache"}
CODE_EXTS = {".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".php", ".java", ".cjs", ".mjs", ".cs", ".kt", ".rb", ".rs"}

# Hints to create better windows; still LLM makes the decisions.
NEEDLES_BASE = [
    # General
    r"\btools?\s*[:=]\s*\[", r"schema\s*:\s*\{\s*name\s*:\s*['\"]", r"\bhandle\s*:\s*",
    r"\bexecute\s*:\s*", r"\brun\s*:\s*", r"\bswitch\s*\(", r"\bcase\s+['\"]",
    # JS/TS
    r"setRequestHandler", r"\bdefineTool\s*\(",
    # Python
    r"@self\.mcp\.tool", r"@mcp\.tool", r"\.add_tool\s*\(", r"Tool\s*\(\s*name\s*=",
    # Java/Kotlin/Go/C#
    r"\bserver\.tool\s*\(", r"\bAddTool\s*\(", r"\bRegisterTool\s*\(",
    r"request\.params\.name\s*==\s*['\"]", r"request\.getParams\(\)\.getName\(\)\.equals\(['\"]",
    # C# Attributes & Generics
    r"\[McpServerTool", r"\[McpServerToolType", r"\.WithTools\s*<",
    r"\bWithToolsFromAssembly\b", r"McpServerTool\.Create\(",
    # PHP Attributes
    r"#\[McpTool",
    # Ruby
    r"server\.define_tool",
    # General Handlers
    r"\bListToolsHandler\b", r"\bCallToolHandler\b",
]


# Cross-language "case <value>:" and "when <value>" patterns.
MULTI_CASE_HEAD_PATTERNS = [
    # C/Java-family patterns: case "foo":, case 'foo':, and case FOO:.
    (r'^\s*case\s+(?P<q>["\']?)(?P<name>[^"\'\n:]+)(?P=q)\s*:\s*$', 'case'),
    # Python: case "foo": / case 'foo': / case foo:
    (r'^\s*case\s+(?P<q>["\']?)(?P<name>[^"\'\n:]+)(?P=q)\s*:\s*$', 'py_case'),
    # Ruby: when "foo" / when :foo / when FOO
    (r'^\s*when\s+(?P<name>.+?)\s*$', 'ruby_when'),
]

# Cross-language default/else patterns.
MULTI_DEFAULT_PATTERNS = [
    (r'^\s*default\s*:\s*$', 'default'),      # C/Java family.
    (r'^\s*case\s+_\s*:\s*$', 'py_default'),  # Python match/case default.
    (r'^\s*else\s*:\s*$', 'py_else'),         # Older Python-style else wrapper.
    (r'^\s*else\s*$', 'ruby_else'),           # Ruby
]

# MODIFIED: Added CRITICAL RULE to prevent hallucination and added handler_definition_file
STAGE1_ANALYZE_AND_PLAN_SYSTEM = r"""You are an expert code analyst specializing in extracting tool handler functions from various programming languages. Your primary goal is to analyze a tool's registration point and create a clear plan for resolving its handler.

**CRITICAL RULE: You MUST ONLY use the information present in the CANDIDATE FILES provided in the user prompt. Do NOT invent, hallucinate, or recall code from your training data. Every piece of code or identifier you output MUST be a direct, verbatim copy from the provided files.**

Valid registrations include (non-exhaustive):
- JavaScript / TypeScript
  - CALL-BASED: `server.tool("<tool>", ..., <handler>)`, `server.registerTool("<tool>", <handler>)`
  - DEFINE-TOOL: `defineTool({ schema: { name: "<tool>", ... }, handle|execute|run: ... })`
  - MAP_OBJECT: `{ "<tool>": <handler>, ... }` or `setRequestHandler` maps
  - DISPATCHER: `tools: [{name:'<tool>',...}]` + a separate `switch(name)`
- Python
  - DECORATORS: `@mcp.tool(name="<tool>")`
  - CALL-BASED: `server.add_tool("<tool>", handler)`
  - DEFINE-TOOL: `Tool(name="<tool>", ...)` in a list `tools=[...]`
- Go
  - CALL-BASED: `mcp.AddTool(server, &mcp.Tool{Name: "<tool>", ...}, handlerFunc)`
  - DISPATCHER: `tools := []Tool{{Name:"<tool>", ...}}` with a separate `switch`
- Java
  - ANNOTATIONS: `@McpServerTool(name="<tool>")` on a method
  - CALL-BASED: `server.addTool("<tool>", handler)`
- Kotlin
  - CALL-BASED (with lambda): `server.addTool(name = "<tool>", ...) { request -> ... }`
- C#
  - ATTRIBUTES: `[McpServerTool(Name="<tool>")]` on a static method.
  - GENERIC/TYPE-BASED: `.WithTools<MyToolClass>()` registers all tools defined in `MyToolClass`.
  - ASSEMBLY SCAN: `.WithToolsFromAssembly()`
- PHP
  - ATTRIBUTES: `#[McpTool(name: '<tool>')]` on a public function.
  - ARRAY: `$server->tool(['tools'=>[['name'=>'<tool>', ...]]])`
- Ruby
  - CALL-BASED (with block): `server.define_tool(name: "<tool>", ...) do |args| ... end`
  - CLASS-BASED: `tools: [MyToolClass]` where `MCP::Tool` inherits from.
- Rust
  - IMPLICIT/STRUCT: `let service = MyToolService::new().serve(...)`. The tools are defined within `MyToolService`.

You must identify THREE main types of handlers:
1.  **INLINE_FUNCTION**: The handler is an anonymous function, lambda, or block defined directly within the tool registration call.
    - JS/TS: `(req) => { ... }` or `function(req) { ... }`
    - Python: `lambda req: ...`
    - Go: `func(req ...) { ... }`
    - Java/Kotlin: `{ req -> ... }` or `new HandlerInterface() { ... }`
    - Ruby: `do |req| ... end`
2.  **IDENTIFIER**: The handler is a reference to a named function that is the **DEDICATED** implementation for **ONLY THIS tool**.
    - JS/TS: `handleGetFills`, `api.handleGetFills`
    - Python: `handle_get_fills`, `self.handle_get_fills`
    - Go: `handleGetFills`, `s.handleGetFills`
    - C#: `HandleGetFills`, `ApiHandlers.HandleGetFills`
3.  **DISPATCHER**: The tool registration points to a **SHARED** handler function that contains logic (like a `switch` or `if/else if` block) to route **DIFFERENT** tools to their respective implementations.
    - e.g., a single `handleToolCall` function that manages multiple tools.

# REVISED: Update the task list to reflect the three types.
**YOUR TASK:**
1.  Locate the exact registration point for the specified tool *within the provided files*.
2.  Determine if the handler is an `INLINE_FUNCTION`, `IDENTIFIER`, or `DISPATCHER`.
3.  **If `INLINE_FUNCTION`**:
    - Set `handler_type` to "INLINE_FUNCTION".
    - Extract the *complete and verbatim* code of the inline function into `handler_code`. This must be a perfect, character-for-character copy.
    - **Crucially, identify the file where this `handler_code` is physically located. Set `handler_definition_file` to this file's path. This may be different from the `registration_file`.**
4.  **If `IDENTIFIER` (a dedicated function for one tool)**:
    - Set `handler_type` to "IDENTIFIER".
    - Extract the identifier's name (e.g., `handleGetFills`) into `handler_identifier`. This name must appear exactly as written in the source code.
    - Analyze imports to generate `resolution_hints` for where that identifier is defined.
5.  **If `DISPATCHER` (a shared routing function)**:
    - Set `handler_type` to "DISPATCHER".
    - Extract the dispatcher function's name (e.g., `handleToolCall`) into `handler_identifier`. This name must appear exactly as written in the source code.
    - Analyze imports to generate `resolution_hints` for where that dispatcher function is defined.

**Output ONLY a strict JSON object with the following schema:**
{
  "tool": "<tool_name>",
  "registration_file": "<path/to/registration/file.ext>",
  "registration_line": <line_number_of_registration>,
  "handler_definition_file": "<path/to/file/containing/the/handler_code.ext, can be null if same as registration_file>",
  "handler_type": "INLINE_FUNCTION | IDENTIFIER | DISPATCHER | UNKNOWN",
  "handler_code": "<The full, multi-line code of the inline function, if applicable. Otherwise, null.>",
  "handler_identifier": "<The handler's name, if it's an identifier or dispatcher. Otherwise, null.>",
  "resolution_hints": [
    "<relative/path/from/import.js>",
    "<another/path.py>"
  ],
  "evidence": "<A brief justification for your findings.>",
  "confidence": <0.0_to_1.0>
}

**IMPORTANT**: If the handler is an `IDENTIFIER` or `DISPATCHER`, the `resolution_hints` array is the most critical part of your output. Adhere strictly to the CRITICAL RULE.
"""



STAGE1_ANALYZE_AND_PLAN_USER_TMPL = Template(r"""Analyze the following code to find the handler for the tool: "$tool"

CANDIDATE FILES:
$packed_code

Follow the system instructions precisely and provide your analysis in the specified JSON format.
""")

# MODIFIED: Stage 2 prompt to return only signature
STAGE2_RESOLVE_IDENTIFIER_SYSTEM = r"""You are a precise code resolver. Your task is to find the specific handler logic for a tool and return its signature.

### Guidance and Examples

Your main task is to find the function's **definition line**. You must actively ignore decorators or attributes that come before it.

**1. DO NOT return decorators or attributes.**
   - For example, avoid returning lines like `@mcp.tool()` or `[McpTool]`. These are incorrect.

**2. DO return the actual function signature.**
   - Look for the keyword that defines the function (e.g., `def`, `function`, `func`, etc.) and return that line.
   - **Examples of what you should return:**
     - **Python:** `def get_categories() -> Dict:`
     - **JavaScript/TypeScript:** `const getCategories = (req) => {`
     - **Java/C#:** `public Response getCategories(Request req)`
     - **PHP:** `public function getCategories($request)`
     - **Go:** `func (s *server) getCategories(w http.ResponseWriter, r *http.Request)`

---

**Rules:**
1.  You will be given a `tool_name` (e.g., "get_weather") and a target `identifier` (a function name, e.g., "handleToolCall").
2.  Search the provided code to find the full definition of the function named `identifier`.
3.  **Inside that function, find the specific logic block that handles the EXACT `tool_name` you were given.**
    - This is typically inside a `switch` statement (e.g., `case "get_weather":`) or an `if/else-if` chain (e.g., `if (toolName === "get_weather")`).
    - The tool name string in the code must EXACTLY match the `tool_name` you are searching for.
4.  **If the handler is a `DISPATCHER`**, the logic block is the specific `case` or `if` statement.
5.  **If the handler is a standard `IDENTIFIER`**, the logic block is the entire function definition.
6.  Once you identify the correct logic block, you MUST extract **ONLY its first line**. This first line is the "signature".
7.  The `signature` you return MUST be a **verbatim, character-for-character copy** from the source, preserving all original indentation and spacing.
8.  **Signature Definition:** The `signature` is the function/method declaration line itself (e.g., `public function createStore(...)` or `def create_store(...)`). You MUST IGNORE any preceding decorator or attribute lines (e.g., lines starting with `@` or `#[`). Return the line with the `function` or `def` keyword.

**Output ONLY a strict JSON object with the following schema:**
{
  "identifier_found": true | false,
  "definition_file": "<path/to/file/where/definition/was/found.ext>",
  "signature": "<The single, verbatim first line of the handler logic (the signature). Null if not found.>"
}
If the identifier or the specific tool's logic cannot be found, return `{"identifier_found": false, "signature": null, ...}`.
"""

# MODIFIED: Stage 2 user template to pass the tool name
STAGE2_RESOLVE_IDENTIFIER_USER_TMPL = Template(r"""Find the specific handler code for the tool: "$tool_name"

The logic is located within the function/identifier: "$identifier"

CONTEXT FROM RELEVANT FILES:
$packed_code

Follow the system instructions to extract the precise code block (either the specific 'case' from a dispatcher, or the entire function if it's a direct handler). Provide your result in the specified JSON format.
""")

# REVISED: Prompt for Stage 3 - Verification and Final Extraction
# REVISED: Prompt for Stage 3 - Verification and Index Selection
STAGE3_VERIFY_AND_SELECT_SYSTEM = r"""You are a code verification expert. Your task is to determine which of several candidate code blocks is the true and complete handler for a specific tool.

You will be given:
1.  **Tool Name**: The name of the high-level tool being implemented.
2.  **Handler Type**: "IDENTIFIER" or "DISPATCHER".
3.  **Target Handler Snippet**: A signature or incomplete code snippet for the handler.
4.  **Numbered Candidate Definitions**: A list of complete functions/blocks extracted from the source code.

**YOUR TASK:**
1.  Analyze all the information provided.
2.  **PRIMARY GOAL: Match by Name.** Your first and most important job is to find the candidate function whose name **exactly matches the `TOOL_NAME`**.
    - For example, if `TOOL_NAME` is "get_categories", you should give the highest priority to the candidate defined as `def get_categories(...)` or `function get_categories(...)`.

3.  **SECONDARY GOAL: Match by Snippet.** If and only if you cannot find any candidate with a matching name, then use the `TARGET_HANDLER_SNIPPET` as a secondary clue to find the best possible match.

4.  **CRITICAL JUDGEMENT:** If the `TARGET_HANDLER_SNIPPET` is generic and useless (like `@mcp.tool()`), you MUST ignore it and rely **solely on the `TOOL_NAME`** to make your choice.
5.  Choose the single best candidate that represents the complete and correct implementation of the handler.
    - If `Handler Type` is `DISPATCHER`, the best candidate should be the one containing the specific logic (e.g., the `case` statement) for the `Tool Name`.
    - If `Handler Type` is `IDENTIFIER`, the best candidate should be the full function definition.
6.  You MUST return only the 1-based index of your chosen candidate. Do NOT return any code.

**Output ONLY a strict JSON object with the following schema:**
{
  "best_candidate_index": <The 1-based index of the most plausible candidate function. -1 if no suitable candidate is found.>,
  "confidence": <A float from 0.0 to 1.0 indicating your certainty>,
  "reasoning": "<A brief explanation for your choice, mentioning why it's a better fit than others if applicable.>"
}

For example, if you believe Candidate 3 is the correct one, you will return `{"best_candidate_index": 3, ...}`.
"""

STAGE3_VERIFY_AND_SELECT_USER_TMPL = Template(r"""TOOL_NAME: "$tool_name"
HANDLER_TYPE: "$handler_type"

TARGET_HANDLER_SNIPPET (Identified by a previous step):
```
$target_snippet
```

CANDIDATE_DEFINITIONS (Extracted from the code):
$candidate_blocks

Please analyze the candidates and choose the one that is the most likely complete definition for the target snippet. Provide your answer in the specified JSON format, returning only the index of the best candidate.
""")



# =================== PROMPTS (Refined) ===================
REG_SNIPPETS = {
    "js_ts": """- JavaScript / TypeScript
  - CALL-BASED: `server.tool("<tool>", ..., <handler>)`, `server.registerTool("<tool>", <handler>)`
  - DEFINE-TOOL: `defineTool({ schema: { name: "<tool>", ... }, handle|execute|run: ... })`
  - MAP_OBJECT: `{ "<tool>": <handler>, ... }` or `setRequestHandler` maps
  - DISPATCHER: `tools: [{name:'<tool>',...}]` + a separate `switch(name)`""",
    "python": """- Python
  - DECORATORS: `@mcp.tool(name="<tool>")`
  - CALL-BASED: `server.add_tool("<tool>", handler)`
  - DEFINE-TOOL: `Tool(name="<tool>", ...)` in a list `tools=[...]`""",
    "go": """- Go
  - CALL-BASED: `mcp.AddTool(server, &mcp.Tool{Name: "<tool>", ...}, handlerFunc)`
  - DISPATCHER: `tools := []Tool{{Name:"<tool>", ...}}` with a separate `switch`""",
    "java": """- Java
  - ANNOTATIONS: `@McpServerTool(name="<tool>")` on a method
  - CALL-BASED: `server.addTool("<tool>", handler)`""",
    "kotlin": """- Kotlin
  - CALL-BASED (with lambda): `server.addTool(name = "<tool>", ...) { request -> ... }`""",
    "csharp": """- C#
  - ATTRIBUTES: `[McpServerTool(Name="<tool>")]` on a static method.
  - GENERIC/TYPE-BASED: `.WithTools<MyToolClass>()` registers all tools defined in `MyToolClass`.
  - ASSEMBLY SCAN: `.WithToolsFromAssembly()`""",
    "php": """- PHP
  - ATTRIBUTES: `#[McpTool(name: '<tool>')]` on a public function.
  - ARRAY: `$server->tool(['tools'=>[['name'=>'<tool>', ...]]])`""",
    "ruby": """- Ruby
  - CALL-BASED (with block): `server.define_tool(name: "<tool>", ...) do |args| ... end`
  - CLASS-BASED: `tools: [MyToolClass]` where `MCP::Tool` inherits from.""",
    "rust": """- Rust
  - IMPLICIT/STRUCT: `let service = MyToolService::new().serve(...)`. The tools are defined within `MyToolService`.""",
}

EXT_LANG_MAP = {
    ".py": "python",
    ".ts": "js_ts",
    ".tsx": "js_ts",
    ".js": "js_ts",
    ".jsx": "js_ts",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
}

def detect_project_languages_for_regs(proj_dir: Path, max_langs: int = 2) -> list[str]:
    counts = {}
    for dp, _, fns in os.walk(proj_dir):
        base = os.path.basename(dp)
        if base in {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".cache", ".idea", ".vscode"}:
            continue
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            key = EXT_LANG_MAP.get(ext)
            if key:
                counts[key] = counts.get(key, 0) + 1
    if not counts:
        return []
    return [k for k, _ in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:max_langs]]

def build_valid_regs_block(langs: list[str]) -> str:
    """Build the valid-registration guidance block for the detected project languages."""
    if not langs:
        langs = ["js_ts", "python"]
    parts = [f"Valid registrations include (non-exhaustive):"]
    for lg in langs:
        if lg in REG_SNIPPETS:
            parts.append(REG_SNIPPETS[lg])
    return "\n".join(parts) + "\n"

def inject_valid_regs_block(system_prompt: str, new_block: str) -> str:
    """Inject the valid-registration guidance block into the system prompt."""
    # Option 1: placeholder replacement for the original list.
    if "<<VALID_REGISTRATIONS>>" in system_prompt:
        return system_prompt.replace("<<VALID_REGISTRATIONS>>", new_block)

    # Option 2: regex replacement for the original list block.
    # Match from the heading line until the next top-level heading, CRITICAL, JSON, or EOF.
    pattern = r"(Valid registrations include \(non-exhaustive\):)(?s).*?(?=\n[A-Z][A-Z \t\-]{3,}\n|\nCRITICAL|\nOutput|\Z)"
    if re.search(pattern, system_prompt):
        return re.sub(pattern, lambda m: new_block.rstrip("\n"), system_prompt, count=1)
    return system_prompt  # Return the prompt unchanged when no matching block is found.

# =================== HELPERS (Mostly unchanged) ===================

def _find_case_anchors(source_text: str) -> List[Tuple[int, Optional[str], str]]:
    """Return dispatcher branch anchors as zero-based line indices, optional labels, and tags."""
    lines = source_text.splitlines()
    anchors: List[Tuple[int, Optional[str], str]] = []
    # case/when
    for rx, tag in MULTI_CASE_HEAD_PATTERNS:
        for m in re.finditer(rx, source_text, flags=re.MULTILINE):
            line0 = source_text[:m.start()].count("\n")
            name = (m.group('name') or '').strip()
            anchors.append((line0, name, tag))
    # default/else
    for rx, tag in MULTI_DEFAULT_PATTERNS:
        for m in re.finditer(rx, source_text, flags=re.MULTILINE):
            line0 = source_text[:m.start()].count("\n")
            anchors.append((line0, None, tag))

    anchors.sort(key=lambda x: x[0])
    return anchors

def split_cases_generic(source_text: str) -> List[Dict]:
    """Split dispatcher-like branch blocks in a simple cross-language way."""
    lines = source_text.splitlines()
    anchors = _find_case_anchors(source_text)
    if not anchors:
        return []

    blocks = []
    for i, (start_ln0, name, tag) in enumerate(anchors):
        end_ln0 = anchors[i + 1][0] if i + 1 < len(anchors) else len(lines)
        block_lines = lines[start_ln0:end_ln0]
        while block_lines and not block_lines[-1].strip():
            block_lines.pop()
        blocks.append({
            "tool_name": name,                   # None means default/else.
            "start_line": start_ln0 + 1,         # 1-based
            "end_line": start_ln0 + len(block_lines),
            "lang_tag": tag,
            "code_block": "\n".join(block_lines),
        })
    return blocks

def _normalize_label(s: str) -> str:
    # Normalize common literal wrappers so values such as quoted strings, symbols, and constants compare evenly.
    t = s.strip()
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        t = t[1:-1]
    if t.startswith(':'):  # Ruby symbol.
        t = t[1:]
    return t.strip()

def detect_dispatcher_cases(source_text: str, tool_name: str) -> List[Dict]:
    """Find branch blocks whose labels match the requested tool name."""
    tool_key = _normalize_label(tool_name)
    blocks = split_cases_generic(source_text)
    hits = []
    for b in blocks:
        if b["tool_name"] is None:   # default / else
            continue
        if _normalize_label(b["tool_name"]) == tool_key:
            hits.append(b)
    return hits

def normalize_stage1_plan(analysis_plan: dict) -> dict:
    """Correct Stage-1 plans when local dispatcher evidence contradicts the handler type."""
    try:
        if analysis_plan.get("handler_type") != "INLINE_FUNCTION":
            return analysis_plan

        tool = (analysis_plan.get("tool") or "").strip()
        reg_file = analysis_plan.get("registration_file")
        if not tool or not reg_file:
            return analysis_plan

        text = Path(reg_file).read_text(encoding="utf-8", errors="ignore")
        hits = detect_dispatcher_cases(text, tool)
        if hits:
            analysis_plan["handler_type"] = "DISPATCHER"
            analysis_plan["handler_identifier"] = "__anonymous_or_dispatcher__"
            hints = analysis_plan.get("resolution_hints", [])
            if "split_cases_in_registration_file" not in hints:
                hints.append("split_cases_in_registration_file")
            analysis_plan["resolution_hints"] = hints
            # Dial confidence back to a high but not excessive value for a strong local correction.
            analysis_plan["confidence"] = max(analysis_plan.get("confidence", 0.0), 0.85)
    except Exception:
        return analysis_plan

    return analysis_plan


def resolve_dispatcher_case_block(
    registration_file: Path | str,
    tool_name: str,
    debug_dir: Path | None = None,
    write_candidates_filename: str | None = None,
) -> Dict:
    """Resolve dispatcher handlers by splitting case or when branches and selecting the matching tool block."""
    try:
        reg_path = Path(registration_file)
        text = reg_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"ok": False, "need_llm_selection": False, "error": f"read registration_file failed: {e}"}

    # 1) Exact mode: keep only case/when sub-blocks that exactly match tool_name.
    exact_blocks = detect_dispatcher_cases(text, tool_name)

    if len(exact_blocks) == 1:
        blk = exact_blocks[0]
        return {
            "ok": True,
            "need_llm_selection": False,
            "start_line": blk["start_line"],
            "end_line": blk["end_line"],
            "code_block": blk["code_block"],
            "match_type": f"dispatcher_exact_case_{blk['lang_tag']}",
            "verified_locally": True,
        }

    if len(exact_blocks) > 1:
        out = {"ok": False, "need_llm_selection": True, "candidates": exact_blocks}
        if debug_dir:
            debug_dir.mkdir(parents=True, exist_ok=True)
            fname = write_candidates_filename or f"{tool_name}__step3_candidates.json"
            fpath = Path(debug_dir) / fname
            try:
                fpath.write_text(json.dumps(exact_blocks, ensure_ascii=False, indent=2), encoding="utf-8")
                out["candidates_path"] = str(fpath)
            except Exception:
                pass
        return out

    # 2) Broad fallback: collect all case/when sub-blocks as candidates.
    all_blocks = split_cases_generic(text)
    if not all_blocks:
        return {"ok": False, "need_llm_selection": False, "error": "no case/when anchors found"}

    # Lightweight heuristic: prefer blocks containing the tool name literal when available.
    heuristics = [b for b in all_blocks if tool_name in (b.get("code_block") or "")]
    candidates = heuristics if heuristics else all_blocks

    out = {
        "ok": False,
        "need_llm_selection": True,
        "candidates": candidates,
        "note": "no exact case matched; falling back to all/heuristic blocks",
    }
    if debug_dir:
        debug_dir.mkdir(parents=True, exist_ok=True)
        fname = write_candidates_filename or f"{tool_name}__step3_candidates.json"
        fpath = Path(debug_dir) / fname
        try:
            fpath.write_text(json.dumps(candidates, ensure_ascii=False, indent=2), encoding="utf-8")
            out["candidates_path"] = str(fpath)
        except Exception:
            pass
    return out




def read_cached_result(debug_dir: Path, filename: str):
    p = debug_dir / filename
    if not p.exists(): return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_cached_result(debug_dir: Path, filename: str, obj):
    debug_dir.mkdir(parents=True, exist_ok=True)
    (debug_dir / filename).write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def read_text_safe(p: Path) -> str:
    try:
        return Path(p).read_text(encoding="utf-8", errors="strict")
    except Exception:
        try:
            return Path(p).read_text(encoding="latin-1", errors="ignore")
        except Exception:
            return ""


def tool_variants(t: str) -> List[str]:
    return list({t, t.replace("_", "-"), t.replace("-", "_")})


def walk_code(root: Path) -> List[Path]:
    out = []
    for r, dnames, fnames in os.walk(root):
        dnames[:] = [d for d in dnames if d not in IGNORE_DIRS]
        for f in fnames:
            p = Path(r) / f
            if p.suffix.lower() in CODE_EXTS:
                out.append(p)
    return out


def scan_candidates_for_tool(root: Path, tool: str) -> List[Path]:
    variants = tool_variants(tool)
    hits = []
    for p in walk_code(root):
        txt = read_text_safe(p)
        if not txt: continue
        score = 0
        if any(re.search(rf'["\']{re.escape(v)}["\']', txt) for v in variants):
            score += 10
        if any(re.search(rf'\b{re.escape(v)}\b', txt) for v in variants):
            score += 1
        if score > 0:
            try:
                size = p.stat().st_size
            except Exception:
                size = 10 ** 9
            hits.append((score, size, p))
    hits.sort(key=lambda x: (-x[0], x[1]))
    return [h[2] for h in hits[:MAX_CANDIDATE_FILES_PER_TOOL]]


def pack_files_as_blocks(paths: List[Path], tool: Optional[str] = None, budget: int = MAX_FILE_BYTES_PER_PROMPT) -> str:
    needles = []
    if tool:
        variants = tool_variants(tool)
        needles = NEEDLES_BASE + [re.escape(v) for v in variants if v]

    blocks, current_size = [], 0
    for p in sorted(set(paths), key=lambda x: x.as_posix()):
        txt = read_text_safe(p)
        if not txt: continue

        # For smaller files or files without tool name hits, include the whole content
        if not tool or len(txt.encode("utf-8")) < 50_000:
            body = txt
        else:  # For large files, create windows around tool name hits
            parts = _line_windows_for_hits(txt, needles, WINDOW_LINES)
            body = ("\n/*...WINDOW...*/\n").join(parts) if parts else (
                    txt[:15000] + "\n/*...TRUNCATED...*/\n" + txt[-15000:])
            if tool not in body:
                body = txt

        block = f"---FILE---\n{p.as_posix()}\n{body}\n---END-FILE---\n\n"
        add_bytes = len(block.encode("utf-8"))
        if current_size + add_bytes > budget:
            remain = budget - current_size
            if remain > 200:
                blocks.append(block[:remain] + "\n/*...TRUNCATED DUE TO PROMPT BUDGET...*/\n")
            break
        blocks.append(block)
        current_size += add_bytes
    return "".join(blocks) if blocks else "(no content provided)"


def _line_windows_for_hits(text: str, needles: List[str], lines_radius: int) -> List[str]:
    if not text: return []
    rx = re.compile("|".join(needles), re.I)
    lines = text.splitlines()
    positions = [text[:m.start()].count("\n") + 1 for m in rx.finditer(text)]
    if not positions: return []
    windows, last_end = [], -10 ** 9
    for ln in sorted(set(positions)):
        s, e = max(0, ln - lines_radius), min(len(lines), ln + lines_radius)
        if s < last_end:
            windows[-1] = (windows[-1][0], e, "\n".join(lines[windows[-1][0]:e]))
        else:
            windows.append((s, e, "\n".join(lines[s:e])))
        last_end = e
    return [w[2] for w in windows[:8]]


def try_parse_or_repair(json_text: str) -> Dict:
    def _load(s: str):
        try:
            return json.loads(s)
        except Exception:
            return None

    s0 = (json_text or "").strip()
    if not s0: return {}
    if (d := _load(s0)) is not None: return d
    s = re.sub(r"^```[a-zA-Z0-9_-]*\s*|\s*```$", "", s0)
    if (d := _load(s)) is not None: return d
    first, last = s.find("{"), s.rfind("}")
    if first != -1 and last != -1 and last > first:
        core = s[first:last + 1]
        core = re.sub(r",\s*([\]}])", r"\1", core)  # Fix trailing commas
        try:
            return json.loads(core)
        except Exception:
            pass
    return {"_raw": json_text}


def resolve_llm_path(p_str: str, proj_root: Path, base_dir: Path | None = None) -> Path | None:
    """Resolve a possibly relative path string to an existing file under proj_root.
    - Robust to forward/backward slashes
    - Avoids premature .resolve() (which can misbehave with symlinks/placeholders)
    - Adds suffix scan fallback
    - Emits helpful debug logs when not found
    """

    def _norm(s: str) -> str:
        # strip quotes/whitespace
        s = (s or "").strip().strip('"').strip("'")
        # unify slashes to /
        s = s.replace("\\\\", "\\").replace("\\", "/")
        # remove only a *single* leading "./" or "/" if present (not greedy lstrip to avoid accidental removals)
        if s.startswith("./"): s = s[2:]
        if s.startswith("/"):  s = s[1:]
        return s

    def _join(base: Path, rel_like: str) -> Path:
        # Split on '/' to avoid OS-dependent quirks
        parts = [p for p in rel_like.split("/") if p not in ("", ".")]
        return base.joinpath(*parts)

    def _exists(p: Path) -> bool:
        # On Windows, OneDrive, or network drives, is_file() is more reliable than exists() for placeholders.
        try:
            return p.is_file() or p.exists()
        except Exception:
            return False

    def _debug_state(title: str, p: Path):
        try:
            print(f"[resolve_llm_path] {title}: {p!s}")
            print(f"  - exists:   {_exists(p)}")
            print(f"  - is_file:  {p.is_file() if p.exists() else 'N/A'}")
            print(f"  - as_posix: {p.as_posix()}")
        except Exception as e:
            print(f"[resolve_llm_path] {title}: <error printing> {e}")

    if not p_str:
        return None

    s_norm = _norm(p_str)

    # 1) If the path is absolute, check it directly without forcing resolve().
    p_in = Path(s_norm)
    if p_in.is_absolute():
        _debug_state("absolute-in", p_in)
        if _exists(p_in):
            return p_in

    # 2) Try the path relative to base_dir first.
    if base_dir:
        cand = _join(base_dir, s_norm)
        _debug_state("try-base-dir", cand)
        if _exists(cand):
            return cand

    # 3) Then try the path relative to proj_root.
    cand = _join(proj_root, s_norm)
    _debug_state("try-proj-root", cand)
    if _exists(cand):
        return cand

    # 4) Try a normpath variant, which is more stable on Windows with mixed separators.
    cand2 = Path(os.path.normpath(str(cand)))
    _debug_state("try-normpath", cand2)
    if _exists(cand2):
        return cand2

    # 5) Finally scan suffixes up to four path segments with case-insensitive matching.
    parts = [p for p in s_norm.split("/") if p]
    for take in range(min(len(parts), 4), 0, -1):
        suffix = "/".join(parts[-take:]).lower()
        try:
            for dp, _, fns in os.walk(proj_root):
                for f in fns:
                    full = Path(dp) / f
                    rel = full.relative_to(proj_root).as_posix().lower()
                    if rel.endswith(suffix):
                        _debug_state("suffix-hit", full)
                        return full
        except Exception as e:
            print(f"[resolve_llm_path] suffix-scan error: {e}")

    # 6) Emit a detailed warning to help debug paths that are visible but fail exists().
    print("[resolve_llm_path] NOT FOUND")
    print(f"  - p_str   : {p_str!r}")
    print(f"  - s_norm  : {s_norm!r}")
    print(f"  - proj_root: {proj_root!s}")
    if base_dir:
        print(f"  - base_dir : {base_dir!s}")
    print("  - Tips:")
    print("    * 确认该文件不是云端占位(OneDrive/Dropbox)；右键‘始终保留在此设备上’后再试。")
    print("    * 在同一 Python 进程里尝试 open(path,'rb') 看是否可读。")
    print("    * 去掉 .resolve() 前置调用，避免 symlink/占位文件导致的 exists() 假阴性。")
    print("    * 用 os.path.exists(str(path)) 对比 Path.exists() 行为。")
    return None


# =================================================================================
# LOCAL VERIFICATION FUNCTION
# =================================================================================

def _normalize_line_for_match(line: str) -> Optional[str]:
    """Normalize a source line for robust signature matching."""
    stripped_line = line.strip()

    # 1) Apply light normalization to decorator and attribute lines.
    if stripped_line.startswith('@') or stripped_line.startswith(('[', '#[')):
        # Keep only letters and digits, then lowercase, preserving the essential signature.
        normalized = re.sub(r'[^a-zA-Z0-9]', '', stripped_line).lower()
        return normalized if normalized else None

    # 2) Use the stricter normalization path for ordinary code lines.
    line = re.sub(r'/\*.*?\*/', '', line)
    line = re.sub(r'(//|#).*$', '', line)
    line = re.sub(r'[\s,;"\'(){}\[\]=:]+', '', line)

    return line.lower() if line else None


def _extract_block_from_start_line(source_lines: List[str], start_idx: int) -> Optional[Dict]:
    """Extract a minimal complete code block across supported language styles."""
    if start_idx >= len(source_lines):
        return None

    # --- 1. Scan downward to find the actual code start line ---
    actual_code_start_idx = -1
    for i in range(start_idx, len(source_lines)):
        line = source_lines[i].strip()
        if not line or line.startswith('#'): continue  # Skip empty/comment lines
        # Keep Python decorators for now, as they are handled by the Python logic
        if line.startswith('@') and not line.endswith(':'): continue
        actual_code_start_idx = i
        break

    if actual_code_start_idx == -1:
        print(f"  -> Extraction failed: No executable code found after line {start_idx + 1}.")
        return None

    # --- 2. Detect the language style ---
    start_line_content = source_lines[actual_code_start_idx].strip()
    is_python = start_line_content.startswith(('def ', 'async def ', 'class ')) and start_line_content.endswith(':')
    is_ruby = start_line_content.startswith(('def ', 'class ', 'module ')) and not start_line_content.endswith(':')

    block_physical_start_idx = start_idx  # Physical start of the final code block, including decorators and annotations.

    # --- 3. Use extraction logic for the detected language style ---

    # Branch A: Python, indentation-based.
    if is_python:
        # Python logic is the same as in the previous version.
        block_content, base_indent, signature_found = [], -1, False
        for i in range(block_physical_start_idx, len(source_lines)):
            line = source_lines[i]
            if base_indent == -1 and i == actual_code_start_idx:
                base_indent = len(line) - len(line.lstrip())
            if signature_found:
                if not line.strip():
                    block_content.append(line);
                    continue
                if (len(line) - len(line.lstrip())) <= base_indent: break
            block_content.append(line)
            if not signature_found and i >= actual_code_start_idx:
                if line.strip().endswith(':'): signature_found = True
        while block_content and not block_content[-1].strip(): block_content.pop()
        return {"start_line": block_physical_start_idx + 1, "end_line": block_physical_start_idx + len(block_content),
                "code_block": "\n".join(block_content)}

    # Branch B: Ruby, based on the 'end' keyword.
    elif is_ruby:
        block_content = []
        nesting_level = 0
        # Ruby block-start keywords.
        ruby_open_keywords = re.compile(r"^\s*(def|class|module|if|unless|case|while|until|for|begin|do)\b")
        ruby_end_keyword = re.compile(r"^\s*end\b")

        for i in range(actual_code_start_idx, len(source_lines)):
            line = source_lines[i]
            block_content.append(line)

            # Check whether this line closes a block.
            if ruby_end_keyword.match(line.strip()):
                nesting_level -= 1
            # Check whether this line starts a block and is not the same-line 'end'.
            elif ruby_open_keywords.match(line.strip()):
                nesting_level += 1

            # Nesting level zero means the matching 'end' has been found.
            if nesting_level == 0:
                break

        prefix_lines = source_lines[block_physical_start_idx:actual_code_start_idx]
        full_block = prefix_lines + block_content
        return {"start_line": block_physical_start_idx + 1, "end_line": block_physical_start_idx + len(full_block),
                "code_block": "\n".join(full_block)}

    # Branch C: C-style and generic languages, using braces and case labels.
    else:
        is_case_block = start_line_content.startswith('case ')
        if is_case_block:
            # Case logic is the same as in the previous version.
            block_content = []
            for line_num in range(actual_code_start_idx, len(source_lines)):
                line = source_lines[line_num]
                stripped_line = line.strip()
                if line_num > actual_code_start_idx and (
                        stripped_line.startswith('case ') or stripped_line.startswith('default:')):
                    break
                block_content.append(line)
            while block_content and not block_content[-1].strip(): block_content.pop()
            prefix_lines = source_lines[block_physical_start_idx:actual_code_start_idx]
            full_block = prefix_lines + block_content
            return {"start_line": block_physical_start_idx + 1, "end_line": block_physical_start_idx + len(full_block),
                    "code_block": "\n".join(full_block)}
        else:
            # Branch D: fallback, collect until the next likely top-level definition.
            block_content, brace_level, first_brace_found = [], 0, False
            for line_num in range(actual_code_start_idx, len(source_lines)):
                line = source_lines[line_num]
                block_content.append(line)
                if not first_brace_found and '{' in line: first_brace_found = True
                if first_brace_found:
                    brace_level += line.count('{')
                    brace_level -= line.count('}')
                    if brace_level <= 0:
                        prefix_lines = source_lines[block_physical_start_idx:actual_code_start_idx]
                        full_block = prefix_lines + block_content
                        return {"start_line": block_physical_start_idx + 1,
                                "end_line": block_physical_start_idx + len(full_block),
                                "code_block": "\n".join(full_block)}
    return None

def _find_by_identifier(
    source_lines: List[str],
    handler_identifier: str,
    file_suffix: str,
) -> List[int]:
    """Locate a function or method definition start line for a handler identifier."""
    if not handler_identifier:
        return []

    parts = [p for p in handler_identifier.split('.') if p]
    method = parts[-1]
    receiver = None
    if len(parts) >= 2 and parts[-2] not in ('self', 'this', 's', 'h', 'srv'):
        receiver = parts[-2]

    hits: List[int] = []
    ext = file_suffix.lower()
    m_esc = re.escape(method)

    if ext == '.go':
        if receiver:
            r_esc = re.escape(receiver)
            pat = re.compile(
                rf'^\s*func\s*\(\s*\w+\s+\*?\s*{r_esc}\s*\)\s*{m_esc}\s*\(',
                re.IGNORECASE,
            )
        else:
            pat = re.compile(rf'^\s*func\s+{m_esc}\s*\(')
        for i, ln in enumerate(source_lines):
            if pat.search(ln):
                hits.append(i)

    elif ext == '.py':
        pat = re.compile(rf'^\s*(?:async\s+)?def\s+{m_esc}\s*\(')
        for i, ln in enumerate(source_lines):
            if pat.search(ln):
                hits.append(i)

    elif ext in {'.js', '.ts', '.jsx', '.tsx', '.cjs', '.mjs'}:
        pats = [
            re.compile(rf'^\s*(?:async\s+)?{m_esc}\s*\('),
            re.compile(rf'^\s*(?:export\s+)?(?:async\s+)?function\s+{m_esc}\s*\('),
            re.compile(rf'(?:const|let|var)\s+{m_esc}\s*='),
            re.compile(rf'\.{m_esc}\s*=\s*(?:async\s*)?(?:function|\()'),
        ]
        for i, ln in enumerate(source_lines):
            if any(p.search(ln) for p in pats):
                hits.append(i)

    elif ext in {'.java', '.kt', '.cs'}:
        pat = re.compile(rf'\b{m_esc}\s*\([^;]*\)\s*\{{?\s*$')
        for i, ln in enumerate(source_lines):
            if pat.search(ln):
                hits.append(i)

    elif ext == '.rb':
        pat = re.compile(rf'^\s*def\s+(?:self\.)?{m_esc}\b')
        for i, ln in enumerate(source_lines):
            if pat.search(ln):
                hits.append(i)

    elif ext == '.php':
        pat = re.compile(rf'\bfunction\s+{m_esc}\s*\(')
        for i, ln in enumerate(source_lines):
            if pat.search(ln):
                hits.append(i)

    elif ext == '.rs':
        pat = re.compile(rf'^\s*(?:pub\s+)?(?:async\s+)?fn\s+{m_esc}\s*[\(<]')
        for i, ln in enumerate(source_lines):
            if pat.search(ln):
                hits.append(i)

    return hits

def strip_mcp_annotations(code: str) -> str:
    """Remove MCP-specific annotations and decorators while preserving following definitions."""

    # Match the first non-empty signature line from the candidate block.
    PAREN_CONTENT = r"""(?:
        [^()"']+                          # non-parenthesis/non-quote characters
      | "(?:\\.|[^"\\])*"                 # double-quoted string
      | '(?:\\.|[^'\\])*'                 # single-quoted string
      | \((?:[^()"'"]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\([^()]*\))*\)  # rare nested parentheses
    )*"""

    # Also compare against normalized source slices to tolerate decorators and annotations.
    # The first line is the most stable anchor.
    #      - @mcp.tool(...) / @mcp.tool()
    #      - @self.mcp.tool(...)
    #      - @<ns>.McpTool(...) / @<ns>.McpServerTool(...)
    #      - @McpTool(...) / @McpServerTool(...)
    decorator_pattern = re.compile(
        rf"""^[ \t]*@
                (?: (?:self\.)?mcp\.tool                                     # mcp.tool / self.mcp.tool
                  | (?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.)?(?:McpTool|McpServerTool)  # optional namespace
                )
                \s*\(
                  {PAREN_CONTENT}
                \)
                [^\n]*\r?\n?                                                 # remove through end of line, including trailing comments
        """,
        re.VERBOSE | re.MULTILINE
    )

    code = decorator_pattern.sub("", code)

    # Bottom-up scan to find decorators or annotations directly attached to the definition.
    # Python decorators: @xxx
    # Java/C#/Spring annotations: @GetMapping(...), @Override
    def _strip_bracket_block(m: re.Match) -> str:
        block = m.group(0)
        # TypeScript or JavaScript decorator support.
        if re.search(r'(?:^|[^\w\.])(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.)?(?:McpTool|McpServerTool)(?:[^\w]|$)',
                     block):
            return ""
        return block  # Attribute or annotation blocks such as #[...] or [...] immediately above the definition.

    # Stop at unrelated code.
    bracket_block_pattern = re.compile(
        r'^[ \t]*\#?\[(?:[^\[\]]|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')*?\]\s*\r?\n?',
        re.MULTILINE | re.DOTALL
    )

    code = bracket_block_pattern.sub(_strip_bracket_block, code)

    return code


def find_code_block_locally(
        client: OpenAI,
        tool: str,
        analysis_plan: Dict,
        source_file_path: Path,
        llm_signature: str,
        start_line_hint: int,
        debug_dir: Path,
        proj_root: Path
) -> Optional[Dict]:
    """Find and verify a handler code block in local source files."""
    if not source_file_path.exists() or not llm_signature:
        return None
    source_lines = read_text_safe(source_file_path).splitlines()

    # Build candidate roots, preserving order and removing duplicates.
    handler_identifier = analysis_plan.get("handler_identifier")
    if handler_identifier and analysis_plan.get("handler_type") == "IDENTIFIER":
        id_hits = _find_by_identifier(
            source_lines, handler_identifier, source_file_path.suffix
        )
        if len(id_hits) == 1:
            block = _extract_block_from_start_line(source_lines, id_hits[0])
            if block:
                print(f"  -> Identifier-based exact match on line {id_hits[0] + 1}.")
                return {**block, "verified_locally": True,
                        "match_type": "identifier_anchor"}
        # Fast path: direct path resolution.
        if not id_hits:
            for sibling in source_file_path.parent.iterdir():
                if (sibling.is_file()
                        and sibling != source_file_path
                        and sibling.suffix.lower() == source_file_path.suffix.lower()
                        and '_test' not in sibling.stem.lower()):
                    sib_lines = read_text_safe(sibling).splitlines()
                    sib_hits = _find_by_identifier(
                        sib_lines, handler_identifier, sibling.suffix
                    )
                    if len(sib_hits) == 1:
                        block = _extract_block_from_start_line(sib_lines, sib_hits[0])
                        if block:
                            print(f"  -> Identifier matched in sibling "
                                  f"{sibling.name} line {sib_hits[0] + 1}.")
                            return {**block,
                                    "verified_locally": True,
                                    "match_type": "identifier_anchor_sibling",
                                    "actual_file": str(sibling)}

        elif len(id_hits) > 1:
            # Fallback: search by basename under likely roots.
            print(f"  -> Identifier matched {len(id_hits)} candidates; "
                  f"will let LLM pick.")

    # Prefer paths containing the hinted relative path suffix.
    if not llm_signature:
        return None
    llm_signature = strip_mcp_annotations(llm_signature)
    #source_lines = read_text_safe(source_file_path).splitlines()
    old_llm_signature = llm_signature
    llm_signatures = llm_signature.split('\n')
    llm_signature = ''

    # Read the file and try AST/signature based extraction first.
    for item in llm_signatures:
        normalized_item = _normalize_line_for_match(item)
        if normalized_item and len(normalized_item) > 2:
            llm_signature = item
            break

    normalized_signature = _normalize_line_for_match(llm_signature)

    if not normalized_signature:
        print(
            f"  -> Warning: Stage 2 returned an invalid signature ('{old_llm_signature}') that became empty after normalization.")
        return None

    # Last resort: local text search around the handler name.
    candidates = []
    high_confidence_candidates = []

    for i, line in enumerate(source_lines):
        normalized_line = _normalize_line_for_match(line)
        if normalized_line and normalized_signature in normalized_line:
            is_mcp_tool = False
            for j in range(i - 1, max(-1, i - 5), -1):
                prev_line = source_lines[j].strip()
                if "@mcp.tool" in prev_line:
                    is_mcp_tool = True
                    break
                if prev_line and not prev_line.startswith('@'):
                    break

            block = _extract_block_from_start_line(source_lines, i)
            if not block: continue

            if any(c['code_block'] == block['code_block'] for c in candidates):
                continue

            if is_mcp_tool:
                print(f"  -> Found high-confidence signature match on line {i + 1} (with @mcp.tool decorator).")
                high_confidence_candidates.append(block)
            else:
                print(f"  -> Found potential signature match on line {i + 1}.")
            candidates.append(block)

    if len(high_confidence_candidates) == 1:
        print("  -> Selecting the single high-confidence candidate directly.")
        return {**high_confidence_candidates[0], "verified_locally": True, "match_type": "unique_decorator_match"}

    final_candidates = high_confidence_candidates if high_confidence_candidates else candidates

    if not final_candidates:
        print("  -> No local candidates found matching the signature.")
        return None

    write_cached_result(debug_dir, f"{tool}__step3_candidates.json", final_candidates)

    if len(final_candidates) == 1:
        print("  -> Exactly one local candidate found. Selecting it directly.")
        return {**final_candidates[0], "verified_locally": True, "match_type": "single_candidate"}

    print(f"  -> Found {len(final_candidates)} ambiguous candidates. Asking LLM to select the best one.")

    handler_type = analysis_plan.get("handler_type", "IDENTIFIER")
    cand_blocks_str = []
    for i, c in enumerate(final_candidates, 1):
        block = (
            f"---CANDIDATE {i} (lines {c['start_line']}-{c['end_line']})---\n"
            f"{c['code_block']}\n"
            f"---END CANDIDATE {i}---\n"
        )
        cand_blocks_str.append(block)

    user3 = STAGE3_VERIFY_AND_SELECT_USER_TMPL.substitute(
        tool_name=tool,
        handler_type=handler_type,
        target_snippet=old_llm_signature,
        candidate_blocks="\n".join(cand_blocks_str)
    )

    selection_result = run_chat_completion(client, MODEL_VERIFY, STAGE3_VERIFY_AND_SELECT_SYSTEM, user3, tool,
                                           debug_dir, "step3_verify")
    write_cached_result(debug_dir, f"{tool}__step3_selection_result.json", selection_result)

    best_idx = selection_result.get("best_candidate_index")

    if best_idx is not None and isinstance(best_idx, int) and 1 <= best_idx <= len(final_candidates):
        print(f"  -> LLM selected candidate #{best_idx}.")
        selected_candidate = final_candidates[best_idx - 1]
        return {**selected_candidate, "verified_locally": True, "llm_verified": True}
    else:
        print(f"  -> LLM failed to select a valid candidate index (got: {best_idx}). Verification failed.")
        return None


def run_chat_completion(client: OpenAI, model: str, system_prompt: str, user_prompt: str,
                        tool: str, debug_dir: Path, stage: str) -> Dict:
    debug_dir.mkdir(parents=True, exist_ok=True)
    (debug_dir / f"{tool}__{stage}_prompt.json").write_text(
        json.dumps([{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                   ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            response_format={"type": "json_object"}, temperature=0.1, timeout=POLL_TIMEOUT_SEC,
        )
        raw = resp.choices[0].message.content or ""
        (debug_dir / f"{tool}__{stage}_raw.json").write_text(raw, encoding="utf-8")
        return try_parse_or_repair(raw)
    except Exception as e:
        err = {"error": f"API call failed for {stage}", "details": str(e)}
        (debug_dir / f"{tool}__{stage}_error.json").write_text(json.dumps(err, indent=2, ensure_ascii=False),
                                                               encoding="utf-8")
        return err


def read_tool_names(project_dir: Path) -> List[str]:
    """
    Scan project_dir/output_refined_v1/*.json and return keys whose value has status == "unresolved".
    Falls back to a simple token split if the JSON cannot be parsed.
    """
    output_dir = Path(project_dir) / "output_refined_v1"
    if not output_dir.is_dir():
        print(project_dir)  # keep your original debug print
        return []
    items = project_dir.name.split('__')
    target = os.path.join(output_dir,items[-1]+'.json')
    tool_names: List[str] = []
    data = {}
    if not os.path.exists(target):
        filepath = Path(project_dir)/"grep_tool_extraction.json"
        with open(filepath, 'r', encoding='utf-8') as f:
            datas = json.load(f)
            tool_names = datas['tools']
    else:
        # Try proper JSON first
        try:
            with open(target, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            # Fallback: if the file isn't valid JSON, approximate by splitting tokens
            # (matches your original intention).
            return [t.strip("'\" ") for t in re.split(r"[,;\n\r\t]+", raw) if t.strip().strip("'\"")]

        # If JSON is a dict like { "toolName": {"status": "..."} , ... }
        if isinstance(data, dict):
            for key, value in data.items():
                try:
                    status = value.get("status", "") if isinstance(value, dict) else ""
                    if status == "unresolved":
                        tool_names.append(key)
                except Exception:
                    # Be tolerant to weird shapes
                    continue




    return tool_names, data
# =================== CORE (Per-project) ===================

def process_one_project(proj: Path) -> Tuple[str, Optional[str]]:
    # Resolve project path to be absolute to prevent path mismatch errors later on.
    proj = proj.resolve()

    out_dir = proj / "output_refined_v1"
    debug_dir = out_dir / f"{proj.name}__debug"
    out_dir.mkdir(parents=True, exist_ok=True)
    debug_dir.mkdir(parents=True, exist_ok=True)

    try:
        if not API_KEY or API_KEY.startswith("sk-...") or API_KEY == "sk-your-key":
            raise RuntimeError("Please set a valid API key (DASHSCOPE_API_KEY env or edit script).")
        client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

        tools, old_results = read_tool_names(proj)
        if not tools:
            #(out_dir / f"{proj.name}.json").write_text(
            #    json.dumps({"project": proj.name, "note": "no tools found"}, indent=2), encoding="utf-8")
            return proj.name, None

        final_results: Dict[str, Dict] = {}

        for t in tools:
            #if t != "add_formula":
            #    continue
            print(f"[{proj.name}] Processing tool: {t}")
            # ---------- Step 1: Analyze & Plan ----------
            cand_paths = scan_candidates_for_tool(proj, t)
            packed_cands = pack_files_as_blocks(cand_paths, t)

            user1 = STAGE1_ANALYZE_AND_PLAN_USER_TMPL.substitute(tool=t, packed_code=packed_cands)
            analysis_plan = run_chat_completion(client, MODEL_ANALYZE, STAGE1_ANALYZE_AND_PLAN_SYSTEM, user1, t,
                                                debug_dir, "step1_analyze")
            

            #user1 = STAGE1_ANALYZE_AND_PLAN_USER_TMPL.substitute(tool=t, packed_code=packed_cands)
            # If the local resolver found a narrower block, prefer it over a broad dispatcher body.
            # This avoids sending the entire dispatcher to downstream analysis.
            #_valid_regs_block = build_valid_regs_block(_langs)
            #_stage1_system = inject_valid_regs_block(STAGE1_ANALYZE_AND_PLAN_SYSTEM, _valid_regs_block)
            #print(_stage1_system)
            #analysis_plan = run_chat_completion(client, MODEL_ANALYZE, _stage1_system, user1, t,
            #    debug_dir, "step1_analyze")
            # Local correction: if Stage 1 mislabels a dispatcher as inline, force DISPATCHER.
            print('***********************************************')
            print(analysis_plan)
            print('***********************************************')
            analysis_plan = normalize_stage1_plan(analysis_plan)
            write_cached_result(debug_dir, f"{t}__step1_analysis_plan.json", analysis_plan)

            handler_type = analysis_plan.get("handler_type")
            reg_file_str = analysis_plan.get("registration_file")
            # MODIFIED: Get the explicit definition file path from the analysis plan
            def_file_str = analysis_plan.get("handler_definition_file")

            if handler_type == "UNKNOWN" or not reg_file_str:
                final_results[t] = {"status": "unresolved", "reason": "Step 1 failed to analyze registration.",
                                    "details": analysis_plan}
                continue
            handler_definition_path = None
            if def_file_str and len(def_file_str) > 2:
                handler_definition_path = resolve_llm_path(def_file_str, proj_root=proj)
                if not handler_definition_path:
                    if def_file_str.endswith('.js'):
                        handler_definition_path = resolve_llm_path(def_file_str.replace('.js', '.ts'), proj_root=proj)
                    elif def_file_str.endswith('.ts'):
                        handler_definition_path = resolve_llm_path(def_file_str.replace('.ts', '.js'), proj_root=proj)
            reg_file_path = resolve_llm_path(reg_file_str, proj_root=proj)
            if not reg_file_path:
                if reg_file_str.endswith('.js'):
                    reg_file_path = resolve_llm_path(reg_file_str.replace('.js', '.ts'), proj_root=proj)
                elif reg_file_str.endswith('.ts'):
                    reg_file_path = resolve_llm_path(reg_file_str.replace('.ts', '.js'), proj_root=proj)

            if not reg_file_path:
                final_results[t] = {"status": "unresolved",
                                    "reason": f"Step 1 returned non-existent registration path: {reg_file_str}"}
                continue

            llm_code_block = None
            handler_file_path = None
            start_line_hint = 1

            if t == "getMultisigTransaction":
                print('d')

            # ---------- Step 2: Resolve & Verify ----------
            if handler_type == "INLINE_FUNCTION":
                print(f"  -> Handler is INLINE_FUNCTION. Verifying locally.")
                llm_code_block = analysis_plan.get("handler_code")

                # MODIFIED: Prioritize the handler_definition_file if it exists, otherwise fallback to registration_file
                if def_file_str:
                    print(f"  -> Analysis provided specific handler definition file: {def_file_str}")
                    handler_file_path = resolve_llm_path(def_file_str, proj_root=proj)
                    if not handler_file_path:
                        if def_file_str.endswith('.js'):
                            handler_file_path = resolve_llm_path(def_file_str.replace('.js', '.ts'), proj_root=proj)
                        elif def_file_str.endswith('.ts'):
                            handler_file_path = resolve_llm_path(def_file_str.replace('.ts', '.js'), proj_root=proj)

                if not handler_file_path:
                    print(
                        f"  -> Handler definition file not found or specified, falling back to registration file: {reg_file_str}")
                    handler_file_path = reg_file_path

                start_line_hint = analysis_plan.get("registration_line", 1)

            elif handler_type == "DISPATCHER":
                print("  -> Handler is DISPATCHER. Try local case-split first (cross-language).")
                # If the source file cannot be resolved, keep the plan but mark it as unresolved.
                res = resolve_dispatcher_case_block(
                    registration_file=reg_file_path,
                    tool_name=t,
                    debug_dir=debug_dir,
                    write_candidates_filename=None
                )

                if res.get("ok") and not res.get("need_llm_selection"):
                    # Resolve dispatcher case blocks before falling back to broader extraction.
                    final_results[t] = {
                        "status": "resolved",
                        "analysis": analysis_plan,
                        "handler": {
                            "file": reg_file_path.relative_to(proj).as_posix(),
                            "start_line": res["start_line"],
                            "end_line": res["end_line"],
                            "code_block": res["code_block"],
                            "verified_locally": True,
                            "match_type": res.get("match_type", "dispatcher_exact_case")
                        }
                    }
                    continue

                if res.get("need_llm_selection"):
                    # Fallback to local handler lookup.
                    print(f"  -> Found {len(res['candidates'])} candidate case-blocks. Asking LLM (Stage 3) to select.")
                    cand_blocks = res["candidates"]
                    cand_blocks_str = []
                    for i, c in enumerate(cand_blocks, 1):
                        cand_blocks_str.append(
                            f"---CANDIDATE {i} (lines {c['start_line']}-{c['end_line']})---\n"
                            f"{c['code_block']}\n"
                            f"---END CANDIDATE {i}---\n"
                        )

                    user3 = STAGE3_VERIFY_AND_SELECT_USER_TMPL.substitute(
                        tool_name=t,
                        handler_type="DISPATCHER",
                        target_snippet=f'case "{t}": ...',
                        candidate_blocks="\n".join(cand_blocks_str)
                    )
                    selection_result = run_chat_completion(client, MODEL_VERIFY, STAGE3_VERIFY_AND_SELECT_SYSTEM, user3,
                                                           t,
                                                           debug_dir, "step3_verify")
                    write_cached_result(debug_dir, f"{t}__step3_selection_result.json", selection_result)
                    best_idx = selection_result.get("best_candidate_index")

                    if isinstance(best_idx, int) and 1 <= best_idx <= len(cand_blocks):
                        chosen = cand_blocks[best_idx - 1]
                        final_results[t] = {
                            "status": "resolved",
                            "analysis": analysis_plan,
                            "handler": {
                                "file": reg_file_path.relative_to(proj).as_posix(),
                                "start_line": chosen["start_line"],
                                "end_line": chosen["end_line"],
                                "code_block": chosen["code_block"],
                                "verified_locally": True,
                                "llm_verified": True,
                                "match_type": f"dispatcher_case_selected_{chosen.get('lang_tag', '')}"
                            }
                        }
                        continue
                    else:
                        final_results[t] = {
                            "status": "unresolved",
                            "reason": f"Stage3 failed to choose among {len(cand_blocks)} case-block candidates.",
                            "analysis": analysis_plan
                        }
                        continue

                # Save the final extracted block and metadata.
                print("  -> No case anchors or exact match not found. Falling back to legacy Stage2 resolve.")
                identifier = analysis_plan.get("handler_identifier") or "__anonymous_dispatcher__"
                context_paths = {reg_file_path}
                if handler_definition_path and handler_definition_path not in context_paths:
                    context_paths.add(handler_definition_path)
                packed_context = pack_files_as_blocks(list(context_paths))
                packed_context = strip_mcp_annotations(packed_context)

                user2 = STAGE2_RESOLVE_IDENTIFIER_USER_TMPL.substitute(
                    tool_name=t,
                    identifier=identifier,
                    packed_code=packed_context
                )
                resolve_result = run_chat_completion(client, MODEL_RESOLVE, STAGE2_RESOLVE_IDENTIFIER_SYSTEM, user2, t,
                                                     debug_dir, "step2_resolve")
                write_cached_result(debug_dir, f"{t}__step2_resolve_result.json", resolve_result)

                if resolve_result.get("identifier_found"):
                    llm_code_block = resolve_result.get("signature")
                    def_file_str_stage2 = resolve_result.get("definition_file")
                    handler_file_path = resolve_llm_path(def_file_str_stage2, proj_root=proj)
                    if not handler_file_path:
                        if def_file_str_stage2.endswith('.js'):
                            handler_file_path = resolve_llm_path(def_file_str_stage2.replace('.js', '.ts'),
                                                                 proj_root=proj)
                        elif def_file_str_stage2.endswith('.ts'):
                            handler_file_path = resolve_llm_path(def_file_str_stage2.replace('.ts', '.js'),
                                                                 proj_root=proj)
                    start_line_hint = 1
                else:
                    final_results[t] = {"status": "unresolved",
                                        "reason": f"Legacy Stage2 fallback also failed for DISPATCHER.",
                                        "plan": analysis_plan}
                    continue

            elif handler_type == "IDENTIFIER":
                print("  -> Handler is IDENTIFIER. Resolving cross-file (legacy Stage2).")
                identifier = analysis_plan.get("handler_identifier")
                hints = analysis_plan.get("resolution_hints", [])
                if not identifier:
                    final_results[t] = {"status": "unresolved",
                                        "reason": f"Step 1 identified IDENTIFIER but provided no name."}
                    continue

                context_paths = {reg_file_path}
                reg_file_dir = reg_file_path.parent
                # Stage 1 plan file for the current project.
                # Base directory used for resolving relative source paths.
                # Project root used as a broader path-resolution fallback.
                same_pkg_exts = {reg_file_path.suffix.lower()}
                # Output directory for extracted handler blocks.
                if reg_file_path.suffix.lower() in {'.js', '.mjs', '.cjs'}:
                    same_pkg_exts |= {'.js', '.mjs', '.cjs', '.ts'}
                elif reg_file_path.suffix.lower() in {'.ts', '.tsx'}:
                    same_pkg_exts |= {'.ts', '.tsx', '.js'}
                for sibling in reg_file_dir.iterdir():
                    if (sibling.is_file()
                            and sibling.suffix.lower() in same_pkg_exts
                            and '_test' not in sibling.stem.lower()
                            and '.test.' not in sibling.name.lower()
                            and '.spec.' not in sibling.name.lower()):
                        context_paths.add(sibling)
                # Process one Stage 1 plan at a time.
                new_hints = []
                for hint in hints:
                    if hint.endswith('.js'):
                        if hint not in new_hints: new_hints.append(hint)
                        alt = hint.replace('.js', '.ts')
                        if alt not in new_hints: new_hints.append(alt)
                    elif hint.endswith('.ts'):
                        if hint not in new_hints: new_hints.append(hint)
                        alt = hint.replace('.ts', '.js')
                        if alt not in new_hints: new_hints.append(alt)
                for hint in new_hints:
                    p = resolve_llm_path(hint, proj_root=proj, base_dir=reg_file_dir)
                    if p: context_paths.add(p)
                if handler_definition_path and handler_definition_path not in context_paths:
                    context_paths.add(handler_definition_path)

                packed_context = pack_files_as_blocks(list(context_paths))
                packed_context = strip_mcp_annotations(packed_context)
                user2 = STAGE2_RESOLVE_IDENTIFIER_USER_TMPL.substitute(tool_name=t,
                                                                       identifier=identifier,
                                                                       packed_code=packed_context)
                resolve_result = run_chat_completion(client, MODEL_RESOLVE, STAGE2_RESOLVE_IDENTIFIER_SYSTEM, user2, t,
                                                     debug_dir, "step2_resolve")
                write_cached_result(debug_dir, f"{t}__step2_resolve_result.json", resolve_result)

                if resolve_result.get("identifier_found"):
                    llm_code_block = resolve_result.get("signature")
                    def_file_str_stage2 = resolve_result.get("definition_file")
                    handler_file_path = resolve_llm_path(def_file_str_stage2, proj_root=proj)
                    if not handler_file_path:
                        if def_file_str_stage2.endswith('.js'):
                            handler_file_path = resolve_llm_path(def_file_str_stage2.replace('.js', '.ts'),
                                                                 proj_root=proj)
                        elif def_file_str_stage2.endswith('.ts'):
                            handler_file_path = resolve_llm_path(def_file_str_stage2.replace('.ts', '.js'),
                                                                 proj_root=proj)
                    start_line_hint = 1
                else:
                    final_results[t] = {"status": "unresolved",
                                        "reason": f"Could not resolve identifier '{identifier}' in provided context.",
                                        "plan": analysis_plan}
                    continue

            # --- Final Local Verification (Now with LLM selection) ---
            if not llm_code_block or not handler_file_path:
                final_results[t] = {"status": "unresolved",
                                    "reason": "Could not obtain handler code block or file path for verification.",
                                    "plan": analysis_plan}
                continue

            print(f"  -> Verifying final code block in {handler_file_path.relative_to(proj)}...")
            verified_handler = find_code_block_locally(
                client=client,
                tool=t,
                analysis_plan=analysis_plan,
                source_file_path=handler_file_path,
                llm_signature=llm_code_block,
                start_line_hint=int(start_line_hint),
                debug_dir=debug_dir,
                proj_root=proj
            )

            if verified_handler:
                actual_file = verified_handler.pop("actual_file", None)
                handler_path = Path(actual_file) if actual_file else handler_file_path
                final_results[t] = {
                    "status": "resolved",
                    "analysis": analysis_plan,
                    "handler": {
                        "file": handler_path.relative_to(proj).as_posix(),
                        **verified_handler
                    }
                }
            else:
                final_results[t] = {
                    "status": "unresolved",
                    "reason": "Local verification failed. Could not identify a single, valid handler implementation.",
                    "analysis": analysis_plan,
                    "llm_handler_code": llm_code_block
                }

        # ---------- Write per-project output ----------
        for key in old_results:
            if key not in final_results:
                final_results[key] = old_results[key]
        (out_dir / f"{proj.name}.json").write_text(json.dumps(final_results, indent=2, ensure_ascii=False),
                                                   encoding="utf-8")
        return proj.name, None

    except Exception as e:
        import traceback
        error_info = f"{str(e)}\n{traceback.format_exc()}"
        (debug_dir / f"{proj.name}__FATAL.txt").write_text(error_info, encoding="utf-8")
        return proj.name, str(e)


# =================== MAIN ===================

def main():
    projects_old = [p for p in CODE_DIR.iterdir() if p.is_dir() and (p / "grep_tool_extraction.json").exists()]
    if not projects_old:
        print(f"[!] No projects under {CODE_DIR} with grep_tool_extraction.json")
        return
    max_procs = 2#int(os.environ.get("MAX_PROCS", '4'))
    print(f"Found {len(projects_old)} projects. Running with MAX_PROCS={max_procs}.")
    summary = {"processed": 0, "ok": 0, "failed": 0, "errors": {}}
    project_names = ["arbbets__scheduler-mcp","bhushangitfull__file-mcp-smith","big-omega__mem0-mcp","cloudflare__playwright-mcp","qKitNp__sherlock_mcp"]
    projects = []
    '''
    for project in projects_old:
        if project.name in project_names:
            projects.append(project)
    '''

    projects = [p for p in CODE_DIR.iterdir() if p.is_dir() and (p / "grep_tool_extraction.json").exists()]
    # Use ProcessPoolExecutor for parallel project processing
    with ProcessPoolExecutor(max_workers=max_procs) as exe:
        fut2proj = {exe.submit(process_one_project, p): p for p in projects}
        for fut in as_completed(fut2proj):
            proj = fut2proj[fut]
            try:
                name, err = fut.result()
                summary["processed"] += 1
                if err:
                    summary["failed"] += 1
                    summary["errors"][name] = err
                    print(f"[{name}] FAILED: {err}")
                else:
                    summary["ok"] += 1
                    print(f"[{name}] OK")
            except Exception as e:
                summary["processed"] += 1
                summary["failed"] += 1
                summary["errors"][proj.name] = str(e)
                print(f"[{proj.name}] FATAL EXCEPTION: {e}")

    summary_path = CODE_DIR.parent / "output_refined_v1__SUMMARY.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

