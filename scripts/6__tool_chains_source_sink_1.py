import os
import json
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Define the base URL for OpenRouter API
base_url = "https://openrouter.ai/api/v1/chat/completions"

# Define your API key
api_key = "sk-or-v1-xxx"

# Load system prompts
system_prompt = """### Role: You are a senior software security auditor. Task: Mark explicit sources (untrusted inputs) and sinks (dangerous outputs) in the code slices. ONLY explicit locations—no taint analysis or inference.

### Rules:
- Scan main code + shown called functions. Match by EITHER:
  (1) **exact API patterns** from the Matching Hints below, OR
  (2) **semantic method/tool naming**: a method whose name implies a sink action and which receives a user-controlled string-like argument. See the Wrapper-Method Policy and Tool-Name Strong Prior below.
- Mark ONLY types from the lists below. No match → use [].
- Each mark: exact type + short evidence (≤120 chars, one literal code line).
- Do NOT describe data flow, risks, or exploit chains—locations only.
- Third-party/API calls: match semantically (e.g. `requests.get(url)` → source `"external_url_response"` + sink `"outbound_request"`).

### Parameter-to-Source Policy (to reduce noise):
- If a top-level tool/handler/function parameter is clearly caller-controlled and can carry arbitrary text/path/content, mark it as:
  - `{"type": "user_input", "snippet_evidence": "<the parameter line>"}`
- Mark if the parameter name or usage suggests free-form input, e.g.: `command`, `cmd`, `text`, `body`, `content`, `prompt`, `query`, `filename`, `file_path`, `path`, `url`, `working_directory`, `data`, `payload`, `params`.
- Also mark if that parameter is directly passed into a dangerous API (subprocess, HTTP request, file system).
- **Do NOT mark** purely control/numeric/boolean/tuning parameters (e.g. `timeout`, `wait_time`, `retries`, `use_fork`, `terminate_after_wait`) when they are only used for local logic.

### Wrapper-Method Policy (sink side, mirrors the source policy above):
Many codebases wrap dangerous APIs behind internal helpers. Treat the wrapper call site as the sink when ALL of the following hold:
- The method name semantically implies a sink action, e.g.:
  - `execute*`, `exec*`, `run*`, `runCommand*`, `spawn*`, `invoke*`, `shell*` → `exec_shell` (also `process_spawn` if it clearly starts a new process)
  - `eval*`, `evaluate*`, `runCode*`, `executePython*` → `dynamic_code_exec`
  - `write*`, `save*`, `put*`, `append*` (with path-like arg) → `fs_write`
  - `delete*`, `remove*`, `unlink*` (with path-like arg) → `fs_delete`
  - `rename*`, `move*` (with path-like arg) → `fs_rename`
  - `extract*`, `unzip*`, `untar*` → `archive_extract`
  - `send*` + `email`/`mail` in name → `email_send`
  - `query*`, `execSql*`, `runQuery*` (with sql-like arg) → `db_query_exec`
- AND the wrapper receives a user-controlled string-like argument (typically the same parameter you marked as `user_input`).
- Use the deepest/most specific propagating call line as evidence (e.g. `e.executeSecureCommand(ctx, command, ...)`), NOT the outermost handler.

### Tool-Name Strong Prior:
If `tool_name` itself contains action keywords like `shell`, `exec`, `run`, `spawn`, `kill`, `write`, `delete`, `fetch`, `http`, `email`, `query`, `eval` AND the body propagates a user-controlled parameter to any function call, you MUST output at least one corresponding sink. Use the propagating call line as evidence. This prior is to avoid missing sinks when the underlying API is wrapped behind custom helpers.

### Source Types (mark exactly from this list):
[
"user_input","http_request_param","http_header","cookie_value","form_field","file_upload",
"path_param","ws_message","email_input","oauth_callback",
"jwt_token_parse","api_response_parse","external_url_response",
"db_query_read","nosql_query_read","cache_read","env_read","config_read","secret_read",
"credential_store_access","process_input","stdin_read","log_read","event_queue_input",
"webhook_callback","dns_response","xml_parser_input","ldap_query_read","metadata_service_access","fs_read","storage_object_read","memory_read","rag_index_read","ipc_read","cli_arg_read","registry_read"
]

### Sink Types (mark exactly from this list):
[
"fs_write","fs_delete","fs_rename","archive_extract","symlink_create","path_traversal",
"exec_shell","process_spawn","process_kill","privilege_escalation","sandbox_escape","outbound_upload",
"dynamic_code_eval","dynamic_code_exec","template_render","template_injection","deserialization",
"xml_xxe","yaml_exec","db_query_exec","nosql_query_exec","orm_exec","command_injection",
"config_injection","ssrf","outbound_request","open_redirect","dns_exfil","env_write",
"secret_write","token_leak","log_write","cache_write","data_export","email_send",
"notification_send","cron_create","systemd_unit_create","chmod_chown","auth_bypass",
"acl_modification","socket_connect","ws_send","plugin_load","dependency_download",
"dynamic_import","cloud_api_access","storage_object_write","keystore_access","memory_write",
"rag_index_write","shared_state_modify","ldap_bind_exec","system_message_write"
]

### Matching Hints (cross-language; use these AND the Wrapper-Method Policy above):
- Python: `subprocess.run/Popen/call/check_output`, `os.system`, `os.popen`, `pty.spawn` → `exec_shell` (also `process_spawn` if new proc); `shell=True` confirms shell exec.
- Python: `eval(...)`, `exec(...)`, `compile(...)+exec` → `dynamic_code_exec`.
- Node: `child_process.exec/execFile/spawn/fork`, `vm.runInNewContext` → `exec_shell` / `dynamic_code_exec`.
- Go: `exec.Command(...).Run()/Output()/CombinedOutput()/Start()`, `syscall.Exec` → `exec_shell` (also `process_spawn`).
- Java: `Runtime.getRuntime().exec(...)`, `ProcessBuilder(...).start()` → `exec_shell`.
- Rust: `std::process::Command::new(...).spawn()/output()/status()` → `exec_shell`.
- Ruby/PHP: backticks `` `cmd` ``, `system`, `exec`, `Kernel#spawn`, `popen` → `exec_shell`.
- `.kill()` / `os.kill()` / process termination → `process_kill`.
- HTTP/fetch/requests/axios to external URL → `outbound_request`; if the response is parsed/read → `external_url_response`.
- File open/write/path ops → corresponding fs_* sinks/sources.
- **Custom wrappers** matching the Wrapper-Method Policy above are first-class sinks; do not require a literal `subprocess`/`exec.Command` to appear.

### Examples:
Example 1 (Positive - exec_shell, direct API):
Code: subprocess.run(user_cmd)
Output: {"sinks": [{"type": "exec_shell", "snippet_evidence": "subprocess.run(user_cmd)"}]}

Example 2 (Positive - exec_shell, wrapper method, no literal subprocess):
Code:
  command, err := request.RequireString("command")
  h.validator.validateCommand(command)
  return h.executor.execute(ctx, command, useBase64)
tool_name: shell_exec
Output: {
  "sources": [{"type":"user_input","snippet_evidence":"command, err := request.RequireString(\\"command\\")"}],
  "sinks":   [{"type":"exec_shell","snippet_evidence":"h.executor.execute(ctx, command, useBase64)"}]
}
Rationale: Tool name (`shell_exec`) plus wrapper method (`execute`) receiving the user-controlled `command` triggers the Tool-Name Strong Prior + Wrapper-Method Policy.

Example 3 (Negative - no mark):
Code: print(cmd)
Output: {"sinks": []}

Example 4 (Source - http request):
Code: cmd = request.GET.get('cmd')
Output: {"sources": [{"type": "http_request_param", "snippet_evidence": "cmd = request.GET.get('cmd')"}]}

### JSON Output Structure (valid JSON only):
{
  "tool_name": "[Inferred Tool Name]",
  "sources": [
    {
      "type": "[exact type]",
      "snippet_evidence": "[one literal code line ≤ 120 chars]"
    }
  ],
  "sinks": [
    {
      "type": "[exact type]",
      "snippet_evidence": "[one literal code line ≤ 120 chars]"
    }
  ],
  "summary": "Marked X sources and Y sinks."
}"""


# Helper function to load tool code data
def load_tool_code_data(server_dir):
    tool_code_file = os.path.join(server_dir, "tool_codes_compact_v1.json")
    with open(tool_code_file, 'r', encoding="utf-8") as f:
        tool_codes = json.load(f)
    return tool_codes


# Function to create user prompt with code snippets
def create_user_prompt(tool_name, datas):
    # Convert chain to tool name string
    tool_codes = datas['m']
    # Get the source code for each tool in the chain
    code_snippets = ["No code found for this tool."]
    if tool_name in tool_codes:
        code_snippets = tool_codes[tool_name]


    # Construct the user input with tool chain and corresponding code
    user_prompt = {
        "tool_name": tool_name,
        "tool_code_slice": code_snippets
    }

    return "USER INPUT:\n" + json.dumps(user_prompt, indent=4)


# Function to call OpenRouter API and analyze
def analyze_tool_source_sink(server_dir, tool_name, tool_codes):
    # Create user prompt
    user_prompt = create_user_prompt(tool_name, tool_codes)

    # Prepare the payload
    payload = {
        "model": "x-ai/grok-4-fast",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.0,
        "reasoning": {"effort": "high"}
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    # Define a timeout value (in seconds)
    timeout = 600  # Set the timeout to 30 seconds
    retries = 3  # Number of retries in case of failure

    # Retry mechanism for handling errors
    for attempt in range(retries):
        try:
            # Send request to the OpenRouter API
            response = requests.post(base_url, headers=headers, data=json.dumps(payload), timeout=timeout)
            response.raise_for_status()  # Will raise an HTTPError if the response code is not 200
            # If the response is successful, save the response to a file
            output_dir = os.path.join(server_dir, "output_phase_source_sink1")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, tool_name + '.json')
            result = response.json()
            content = result['choices'][0]['message']['content']
            with open(output_file, 'w') as f:
                json.dump(content, f, indent=4)

            print(f"Analysis complete for tool: {tool_name}")
            break  # Exit the retry loop if successful
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
            print(f"Error analyzing tool {tool_name} of json: {e}")
            if attempt < retries - 1:
                print(f"Retrying... (Attempt {attempt + 2}/{retries})")
                time.sleep(5)  # Wait for 5 seconds before retrying
            else:
                print("Max retries reached. Skipping this chain.")
        except requests.exceptions.RequestException as e:
            print(f"Error analyzing tool {tool_name}: {e}")
            if attempt < retries - 1:
                print(f"Retrying... (Attempt {attempt + 2}/{retries})")
                time.sleep(5)  # Wait for 5 seconds before retrying
            else:
                print("Max retries reached. Skipping this chain.")


# Function to process each MCP server
def process_mcp_server(server_dir):

    # Load tool code data
    tool_codes = load_tool_code_data(server_dir)
    filenames = []
    if os.path.exists(server_dir+'/output_phase_source_sink1'):
        filenames = os.listdir(server_dir + '/output_phase_source_sink1')

    datas = tool_codes['m']
    tool_names = []
    for tool_name in datas:
        if tool_name+'.json' in filenames:
            continue

        tool_names.append(tool_name)

    # Create a ThreadPoolExecutor to limit the number of threads
    with ThreadPoolExecutor(max_workers=10) as executor:  # Limit to 5 concurrent threads
        # Analyze each chain using the thread pool
        futures = [executor.submit(analyze_tool_source_sink, server_dir, tool_name, tool_codes) for tool_name in
                   tool_names]

        # Wait for all threads to complete
        for future in futures:
            future.result()  # This will re-raise any exceptions encountered during the thread execution


# Function to process all MCP servers in the input folder.
def process_all_servers(sample_folder):
    # Get all MCP server directories in the input folder.
    server_dirs = [os.path.join(sample_folder, d) for d in os.listdir(sample_folder) if
                   os.path.isdir(os.path.join(sample_folder, d))]

    # Process each server
    for server_dir in server_dirs:
        print(f"Processing MCP Server: {server_dir}")
        #if '0kenx__mcp-servers' in server_dir:
        #    continue
        if not os.path.exists(server_dir+"/tool_codes_compact_v1.json"):
            print(server_dir+"/tool_codes_compact_v1.json")
            continue
        process_mcp_server(server_dir)


# Define the sample folder path
sample_folder = "../mcp_servers_repos"

# Start processing all MCP servers
process_all_servers(sample_folder)
