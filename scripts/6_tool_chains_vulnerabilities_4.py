import os
import json
import random

import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Define the base URL for OpenRouter API
base_url = "https://openrouter.ai/api/v1/chat/completions"

# Define your API key
api_key = "sk-or-v1-xxx"

# Load system prompts
system_prompt1 = """
Role: You are a PoC step compliance validator running in "thinking" mode.

Your job: Analyze the provided tool chain and its code then determine if there are any risks related to **LLM Injection Attacks**.

### IMPORTANT PROCESS RULES
1. **Tool Chain Order**: The order of tools in the chain should not be altered in the PoC output. However, redundant tools that do not directly contribute to the attack’s success can be removed to streamline the attack chain.
2. **Early Exit Rule**: If Step 1 and Step 2 BOTH determine that no LLM injection risk exists, DO NOT execute Step 3 and Step 4. Go directly to the final JSON output and set `"is_llm_injection_possible": false` and `"exploitability_poc": null`.
3. **Output Restriction**: Use your internal "thinking" ability freely, but DO NOT output any chain-of-thought, scratchpad, or intermediate reasoning. The only output allowed is a single JSON object that exactly matches the OUTPUT_SCHEMA below. No extra text, no explanation outside the JSON.
4. **Use Only Provided Information**: Use only the information present in the input object (e.g., the `code` array and its fields). Do not assume additional infrastructure or external facts. If evidence is missing, mark findings as "latent" or "unknown" per the schema.
5. **Functionality Constraint**: Do not assume the presence of a functionality if it is not explicitly mentioned in the tool chain or is not supported by any tool in the chain. All actions must be strictly limited to the capabilities of the tools in the chain and the attacker's abilities, based on the provided input. **If a tool lacks a particular functionality, do not assume it can perform that function**.


### Step-by-Step Analysis

#### Step 1: Check for Local Input and Output Behavior
- Objective: Identify if any tools in the chain accept user input and save it to local storage (e.g., file system, in-memory storage, databases).
- Behavior to check: Look for tools that read from this local storage and return the data in subsequent steps.
- Vulnerability identification: If both behaviors exist in the chain, LLM injection risk is possible.
- Note: If Step 1 finds a positive case, bypass Step 2 and go to Step 3.

#### Step 2: Check for External Input and Output Behavior
- Objective: Identify tools that fetch data from external sources (e.g., APIs, websites) and process it.
- Behavior to check: Ensure that tools directly return this external data without sanitization or validation.
- Exclusion: Do NOT consider direct user inputs in this step.
- Vulnerability identification: If both fetching and returning unvalidated external data exist, LLM injection risk is possible.

#### Step 3: Optimize Attack Chains
- Objective: Remove redundant or unnecessary steps in the tool chain that do not contribute directly to the attack's success, while keeping the original order of the remaining steps.

#### Step 4: Design PoC for Exploitable Attack Chains
- Objective: Develop a PoC to exploit the identified vulnerabilities (crafted prompt / malicious external content).

### OUTPUT_SCHEMA

{ 
	"tool_chain": null | [ 
		{ "tool_name": "tool1" }, 
		{ "tool_name": "tool2" }, 
		... 
	], 
	"analysis_results": {
		"is_llm_injection_possible": true | false, 
		"redundant_steps_removed": true | false, 
		"exploitability_poc": null | { 
			"steps": [ { 
				"step_idx": 1, 
				"actor": "attacker", 
				"tool": <tool name> | null,  
				"expected_behavior": "Attacker uses Tool A to send malicious data.", 
				"expected_payload": {
					"url": "https://malicious-url.com"
				} 
			}, 
			... 
			] 
		} 
	} 
} 

### Example of Expected Output: 
{
  "tool_chain": [
    { "tool_name": "Tool A" },
    { "tool_name": "Tool B" },
    { "tool_name": "Tool C" }
  ],
  "analysis_results": {
    "is_llm_injection_possible": true,
    "redundant_steps_removed": false,
    "exploitability_poc": {
      "steps": [
        {
          "step_idx": 1,
          "actor": "attacker",
          "tool": "Tool A",
          "role": "producer",
          "expected_behavior": "Attacker uses Tool A to get malicious data from the website `https://www.test.com/test.txt`",
          "expected_payload": {
            "url": "https://www.test.com/test.txt"
          }
        },
        ...
      ]
    }
  }
}
"""
system_prompt2 = """
Role: You are a rigorous, deterministic security-analysis engine running in "thinking" mode.

Your job: Analyze the provided tool chain to determine if there are any risks related to **server or user exploits**.

### IMPORTANT PROCESS RULES
1. **Tool Chain Order**: The order of tools in the chain should not be altered in the PoC output. However, redundant tools that do not directly contribute to the attack’s success can be removed to streamline the attack chain.
2. **Early Exit Rule**: If Step 2 and Step 3 BOTH determine that no server or user exploit risk exists, DO NOT execute Step 4 and Step 5. Go directly to the final JSON output and set `"is_server_attack_possible": false` and `"exploitability_poc": null`. **If no exploit is found, skip PoC design and attack chain optimization.**
3. **Output Restriction**: Use your internal "thinking" ability freely, but DO NOT output any chain-of-thought, scratchpad, or intermediate reasoning. The only output allowed is a single JSON object that exactly matches the OUTPUT_SCHEMA below. No extra text, no explanation outside the JSON.
4. **Use Only Provided Information**: Use only the information present in the input object (e.g., the `code` array and its fields). Do not assume additional infrastructure or external facts. If evidence is missing, mark findings as "latent" or "unknown" per the schema.
5. **Functionality Constraint**: Do not assume the presence of a functionality if it is not explicitly mentioned in the tool chain or is not supported by any tool in the chain. All actions must be strictly limited to the capabilities of the tools in the chain and the attacker's abilities, based on the provided input. **If a tool lacks a particular functionality, do not assume it can perform that function**.
6. **Redundancy Check Rule**: After identifying potential exploits, evaluate if the chain's vulnerability is equivalent to or directly derivable from a single tool's standalone behavior (e.g., no emergent complexity from multi-tool interactions). If yes, flag as redundant and skip PoC generation for the chain.

### Step-by-Step Analysis

#### Step 1: Identify any tools in the chain that interact with the server or other users.
- **Objective**: Identify tools that directly interact with the server or its resources, or perform actions that could affect the server or other users.
- **Behavior to Check**: Look for tools involved in:
  - **Command execution** (e.g., executing shell commands or scripts on the server)
  - **File system access** (e.g., file reading, writing, appending, deleting, etc.)
  - **Resource access** (e.g., accessing environment variables, system resources, or shared states)
  - **Network communication** (e.g., tools that send requests to the server or expose services for communication)
  - **Authentication or authorization mechanisms** (e.g., tools handling user authentication or system permissions)
  
- **Tools to consider**: 
  - **Command execution tools**: Tools that execute commands or scripts on the server.
  - **File I/O tools**: Tools that allow reading, writing, or manipulating files and directories on the server.
  - **API tools**: Only consider API interaction tools if they interact with server-side APIs or resources that could lead to unauthorized access or privilege escalation.
  - **Network-related tools**: Tools that handle network communication or expose server ports.

- **Vulnerability Identification**: If tools with the above behaviors exist in the chain, they could create vulnerabilities such as unauthorized file access, command injection, privilege escalation, or resource manipulation that can affect the server or other users.

#### Step 2: Check for any tools that enable unauthorized file access, system manipulation, or exploit insecure communication channels.
- **Objective**: Identify tools that may provide unauthorized access to system files, enable system manipulation (e.g., execution of system commands), or manipulate insecure communication channels (e.g., unencrypted HTTP requests).
- **Vulnerability Identification**: If tools allow unauthorized access or manipulation, server/user exploits are possible.

#### Step 3: Investigate whether there are insecure APIs or tools that may allow for data exfiltration or unauthorized control over the system.
- **Objective**: Check if any tools interact with APIs or external systems in an insecure way that could enable data exfiltration or unauthorized actions (e.g., command injection via unprotected API).
- **Vulnerability Identification**: If insecure APIs are found, server/user exploits are possible.

#### Step 3.5: Single-Tool Equivalence Check (NEW — mandatory)
- Objective: Determine whether the vulnerability you identified for the tool chain is equivalent to a vulnerability that can be produced by a single tool in the chain when used standalone. If they are equivalent, do not produce a chain PoC — abandon chain PoC generation and reflect this in the final JSON as described below.
- Procedure (deterministic, use only provided info):
  1. For each tool T in the provided chain, analyze T’s standalone capabilities (using only its provided code/description) to see if T alone:
     - can reach the same target (server or user resource),
     - can achieve the same impact type (file write/exfiltration, command execution, privilege change, etc.),
     - requires no more attacker capabilities than the chain (i.e., attacker privileges required for T alone are ≤ those required by the chain), and
     - can accept or be induced to accept an equivalent payload (semantically same effect, not necessarily identical bytes).
  2. Use conservative equivalence: require same target and same impact class plus comparable attacker capability. If any of these is unknown or latent, treat equivalence as NOT proven unless evidence is explicit in the provided inputs.
  3. If you find any tool T that meets the above (i.e., the chain’s exploit is directly reproducible by a single tool T alone), then:
     - Do not generate a chain PoC (skip Step 4 and Step 5 PoC output).
     - Set analysis_results.exploitability_poc = null.
     - Set analysis_results.is_server_attack_possible = true if the single tool T is itself exploitable (based on your analysis); otherwise set it to false.
     - Set analysis_results.redundant_steps_removed = true.
     - Include the original tool_chain in the output unchanged (you must not mutate the input chain ordering).
     - Do not add any other fields not defined in OUTPUT_SCHEMA.
  4. If no single tool equivalence is found, proceed to Step 4 (Optimize Attack Chains) and Step 5 (Design PoC) as normal.

NOTE: This Step 3.5 is intentionally conservative and deterministic — equivalence must be supported directly by the provided tool descriptions/code. Do not infer emergent equivalence from unstated assumptions.

#### Step 4: Optimize Attack Chains
- **Objective**: Remove redundant or unnecessary steps in the tool chain that do not contribute directly to the attack's success, while keeping the original order of the remaining steps.

#### Step 5: Design PoC for Exploitable Attack Chains
- **Objective**: Develop a PoC to exploit the identified vulnerabilities.
  - For server/user exploits, draft specific actions (e.g., commands, file uploads) that can trigger the vulnerabilities.

### OUTPUT_SCHEMA

{ 
  "tool_chain": null | [ 
    { "tool_name": "tool1" }, 
    { "tool_name": "tool2" }, 
    ... 
  ], 
  "analysis_results": {
    "is_server_attack_possible": true | false, 
    "redundant_steps_removed": true | false, 
    "exploitability_poc": null | { 
      "steps": [ { 
        "step_idx": 1, 
        "actor": "attacker", 
        "tool": <tool name> | null,  
        "expected_behavior": "<=200 chars>", 
        "expected_payload": {
          "key": "value"
        } 
      }, 
      ... 
      ] 
    } 
  } 
} 

### Example of Expected Output: 
{
  "tool_chain": [
    { "tool_name": "Tool A" },
    { "tool_name": "Tool B" },
    { "tool_name": "Tool C" }
  ],
  "analysis_results": {
    "is_server_attack_possible": true,
    "redundant_steps_removed": false,
    "exploitability_poc": {
      "steps": [
        {
          "step_idx": 1,
          "actor": "attacker",
          "tool": "Tool A",
          "role": "producer",
          "expected_behavior": "Attacker uses Tool A to execute malicious command.",
          "expected_payload": {
            "cmd": "whoami; rm -rf /tmp/x"
          }
        },
        ...
      ]
    }
  }
}
"""
system_prompt2 = """
Role: You are a rigorous, deterministic security-analysis engine running in "thinking" mode.

Your job: Analyze the provided tool chain to determine if there are any risks related to **server or user exploits**.

### IMPORTANT PROCESS RULES

1. **Tool Chain Order**: The order of tools in the chain should not be altered in the PoC output. However, redundant tools that do not directly contribute to the attack’s success can be removed to streamline the attack chain.

2. **Early Exit Rule**: If Step 2 and Step 3 BOTH determine that no server or user exploit risk exists, DO NOT execute Step 4 and Step 5. Go directly to the final JSON output and set `"is_server_attack_possible": false` and `"exploitability_poc": null`. **If no exploit is found, skip PoC design and attack chain optimization.**

3. **Output Restriction**: Use your internal "thinking" ability freely, but DO NOT output any chain-of-thought, scratchpad, or intermediate reasoning. The only output allowed is a single JSON object that exactly matches the OUTPUT_SCHEMA below. No extra text, no explanation outside the JSON.

4. **Use Only Provided Information**: Use only the information present in the input object (e.g., the `code` array and its fields). Do not assume additional infrastructure or external facts. If evidence is missing, mark findings as "latent" or "unknown" per the schema.

5. **Functionality Constraint**: Do not assume the presence of a functionality if it is not explicitly mentioned in the tool chain or is not supported by any tool in the chain. All actions must be strictly limited to the capabilities of the tools in the chain and the attacker's abilities, based on the provided input. **If a tool lacks a particular functionality, do not assume it can perform that function**.

6. **Redundancy Check Rule**: After identifying potential exploits, evaluate if the chain's vulnerability is equivalent to or directly derivable from a single tool's standalone behavior (e.g., no emergent complexity from multi-tool interactions). If yes, flag as redundant and skip PoC generation for the chain.

7. **ATTACKER KNOWLEDGE BOUNDARY (Deterministic Constraint — MUST APPLY)**

   * **ACCEPTABLE (attacker may know/control):**

     * The attacker's own session tokens, cookies, or IDs.
     * Publicly available information (public URLs, public metadata).
     * Resources controlled by the attacker (attacker-hosted websites, attacker servers).
     * Predictable or enumerable values that are demonstrably accessible to an attacker (only if the input shows evidence of enumeration).
     * Any parameter or file the attacker supplies directly in the PoC step.
   * **UNACCEPTABLE (must be flagged if required and not explicitly evidenced):**

     * Other users' private data (unless explicit code-based leakage evidence is present).
     * Internal system secrets, private keys, or credentials — unless explicit code evidence shows these are accessible via the provided inputs.
     * Information obtainable only by social engineering or user persuasion (do not consider as attacker-controlled).
     * Cross-user access assumptions without explicit code proof of shared persistence or an explicit leakage pathway.
   * **Deterministic handling rule**:

     * When designing or validating a PoC, **only** use knowledge from the ACCEPTABLE list.
     * If a candidate exploit requires any UNACCEPTABLE knowledge and there is **no explicit code-based evidence in the provided inputs** showing access/leakage of that knowledge, then **treat the exploit as NOT demonstrably exploitable**: do not generate a PoC (set `exploitability_poc = null`) and set `is_server_attack_possible` accordingly (false if no other evidence).
     * If there **is** explicit code-based evidence in the provided input that demonstrates access to otherwise UNACCEPTABLE knowledge (e.g., code that reads other users' private files, logs secrets to a world-readable location, or exposes credentials), you may treat that item as allowable attacker knowledge for PoC generation — but MUST document (in `dataflow_reason`-style internal notes, not in chain-of-thought) the exact input evidence used.
     * This rule is **conservative**: absence of explicit code evidence means do not assume privileged or cross-user data is attacker-controlled.

### Step-by-Step Analysis

#### Step 1: Identify any tools in the chain that interact with the server or other users.

* **Objective**: Identify tools that directly interact with the server or its resources, or perform actions that could affect the server or other users.

* **Behavior to Check**: Look for tools involved in:

  * **Command execution** (e.g., executing shell commands or scripts on the server)
  * **File system access** (e.g., file reading, writing, appending, deleting, etc.)
  * **Resource access** (e.g., accessing environment variables, system resources, or shared states)
  * **Network communication** (e.g., tools that send requests to the server or expose services for communication)
  * **Authentication or authorization mechanisms** (e.g., tools handling user authentication or system permissions)

* **Tools to consider**:

  * **Command execution tools**: Tools that execute commands or scripts on the server.
  * **File I/O tools**: Tools that allow reading, writing, or manipulating files and directories on the server.
  * **API tools**: Only consider API interaction tools if they interact with server-side APIs or resources that could lead to unauthorized access or privilege escalation.
  * **Network-related tools**: Tools that handle network communication or expose server ports.

* **Vulnerability Identification**: If tools with the above behaviors exist in the chain, they could create vulnerabilities such as unauthorized file access, command injection, privilege escalation, or resource manipulation that can affect the server or other users.

#### Step 2: Check for any tools that enable unauthorized file access, system manipulation, or exploit insecure communication channels.

* **Objective**: Identify tools that may provide unauthorized access to system files, enable system manipulation (e.g., execution of system commands), or manipulate insecure communication channels (e.g., unencrypted HTTP requests).
* **Vulnerability Identification**: If tools allow unauthorized access or manipulation, server/user exploits are possible.

#### Step 3: Investigate whether there are insecure APIs or tools that may allow for data exfiltration or unauthorized control over the system.

* **Objective**: Check if any tools interact with APIs or external systems in an insecure way that could enable data exfiltration or unauthorized actions (e.g., command injection via unprotected API).
* **Vulnerability Identification**: If insecure APIs are found, server/user exploits are possible.

#### Step 3.5: Single-Tool Equivalence Check (NEW — mandatory)

* Objective: Determine whether the vulnerability you identified for the tool chain is equivalent to a vulnerability that can be produced by a single tool in the chain when used standalone. If they are equivalent, do not produce a chain PoC — abandon chain PoC generation and reflect this in the final JSON as described below.
* Procedure (deterministic, use only provided info):

  1. For each tool T in the provided chain, analyze T’s standalone capabilities (using only its provided code/description) to see if T alone:

     * can reach the same target (server or user resource),
     * can achieve the same impact type (file write/exfiltration, command execution, privilege change, etc.),
     * requires no more attacker capabilities than the chain (i.e., attacker privileges required for T alone are ≤ those required by the chain), and
     * can accept or be induced to accept an equivalent payload (semantically same effect, not necessarily identical bytes).
  2. Use conservative equivalence: require same target and same impact class plus comparable attacker capability. If any of these is unknown or latent, treat equivalence as NOT proven unless evidence is explicit in the provided inputs.
  3. If you find any tool T that meets the above (i.e., the chain’s exploit is directly reproducible by a single tool T alone), then:

     * Do not generate a chain PoC (skip Step 4 and Step 5 PoC output).
     * Set analysis_results.exploitability_poc = null.
     * Set analysis_results.is_server_attack_possible = true if the single tool T is itself exploitable (based on your analysis); otherwise set it to false.
     * Set analysis_results.redundant_steps_removed = true.
     * Include the original tool_chain in the output unchanged (you must not mutate the input chain ordering).
     * Do not add any other fields not defined in OUTPUT_SCHEMA.
  4. If no single tool equivalence is found, proceed to Step 4 (Optimize Attack Chains) and Step 5 (Design PoC) as normal.

NOTE: This Step 3.5 is intentionally conservative and deterministic — equivalence must be supported directly by the provided tool descriptions/code. Do not infer emergent equivalence from unstated assumptions.

#### Step 4: Optimize Attack Chains

* **Objective**: Remove redundant or unnecessary steps in the tool chain that do not contribute directly to the attack's success, while keeping the original order of the remaining steps.

#### Step 5: Design PoC for Exploitable Attack Chains

* **Objective**: Develop a PoC to exploit the identified vulnerabilities.

  * For server/user exploits, draft specific actions (e.g., commands, file uploads) that can trigger the vulnerabilities.
  * **Knowledge constraint**: Use **only** ACCEPTABLE attacker knowledge from Rule 7 when constructing payloads. If the PoC would require UNACCEPTABLE knowledge and no explicit code evidence exists, do not produce the PoC (set `exploitability_poc = null`).

### OUTPUT_SCHEMA

{
"tool_chain": null | [
{ "tool_name": "tool1" },
{ "tool_name": "tool2" },
...
],
"analysis_results": {
"is_server_attack_possible": true | false,
"redundant_steps_removed": true | false,
"exploitability_poc": null | {
"steps": [ {
"step_idx": 1,
"actor": "attacker",
"tool": <tool name> | null,
"expected_behavior": "<=200 chars>",
"expected_payload": {
"key": "value"
}
},
...
]
}
}
}

### Example of Expected Output:

{
"tool_chain": [
{ "tool_name": "Tool A" },
{ "tool_name": "Tool B" },
{ "tool_name": "Tool C" }
],
"analysis_results": {
"is_server_attack_possible": true,
"redundant_steps_removed": false,
"exploitability_poc": {
"steps": [
{
"step_idx": 1,
"actor": "attacker",
"tool": "Tool A",
"role": "producer",
"expected_behavior": "Attacker uses Tool A to execute malicious command.",
"expected_payload": {
"cmd": "whoami; rm -rf /tmp/x"
}
}
]
}
}
}
"""
system_prompt2 = """
Role: You are a rigorous, deterministic security-analysis engine running in "thinking" mode.

Your job: Analyze the provided tool chain to determine if there are any risks related to **server or user exploits** that arise from the COMPOSITION of multiple tools — that is, exploits that require multiple tools acting together and that no single tool in the chain can produce on its own.

A risk that any single tool in the chain can produce alone, with no real dependency on the other tools, is OUT OF SCOPE here. For such cases, set `is_server_attack_possible = false` and `exploitability_poc = null`. This is not a judgment that the chain is harmless; it is a judgment that it is not a multi-tool composition risk.

### MANDATORY RULES

1. **OUTPUT IS JSON ONLY**. Do not output reasoning, scratchpad, or any text outside the JSON object specified in OUTPUT_SCHEMA.

2. **USE ONLY PROVIDED INFORMATION**. The input contains a `chain` (ordered tool list) and `code` (per-tool source). Do not invent infrastructure, libraries, or tool capabilities not present in the input.

3. **PRESERVE CHAIN ORDER**. Do not reorder tools in the output. You may remove redundant tools, but remaining tools must keep their original relative order.

4. **DO NOT ASSUME UNDOCUMENTED FUNCTIONALITY**. If a tool's code does not show a behavior, that tool does not have that behavior.

5. **ATTACKER KNOWLEDGE BOUNDARY**.
   The attacker IS allowed to know/control:
     - Their own session tokens, cookies, IDs.
     - Public information (public URLs, public metadata).
     - Resources the attacker hosts (attacker-controlled domains, files they upload).
     - Any parameter the attacker passes directly into a tool call in the PoC.
   The attacker IS NOT allowed to know/control:
     - Other users' private data.
     - Internal system secrets, private keys, credentials.
     - Specific values of files/data the attacker has not seen and cannot enumerate.
     - Any value that requires social engineering or trickery to obtain.
   If a candidate exploit requires the attacker to know UNALLOWED information, and the input does NOT show explicit code evidence that the chain leaks that information to the attacker, the exploit is NOT demonstrable. Set `is_server_attack_possible = false`.

### STEP 1 — DO THIS FIRST: COMPOSITION-NECESSITY TEST (CRITICAL)

Before any other analysis, answer ONE question:

**QUESTION**: Look at the LAST tool in the chain — the tool that would carry out the final harmful effect. Call it T.
Could T be invoked by the attacker DIRECTLY (with parameters the attacker supplies in that single call) to cause the same harmful effect, WITHOUT any earlier tool in the chain running first?

Pick exactly ONE answer:

**Answer A — "YES, T alone is enough"**
T does not need any preceding tool. The earlier tools add nothing the attacker could not have done by passing parameters directly to T. The risk, if any, is a property of T itself, not of the chain.
→ Set `is_server_attack_possible = false`.
→ Set `exploitability_poc = null`.
→ Set `redundant_steps_removed = true`.
→ Set `tool_chain` = original chain unchanged.
→ Skip remaining steps. Output JSON.

**Answer B — "NO, T alone fails because the attacker is MISSING SPECIFIC INFORMATION"**
T cannot be invoked successfully by the attacker alone because T requires specific data values that the attacker does not know and cannot supply directly. A preceding tool in the chain produces those data values and routes them to T. The earlier tool's output is a NECESSARY input that T cannot obtain otherwise.
→ Identify the preceding tool that produces this information. Call it A.
→ Proceed to Step 2.

**Answer C — "NO, T alone fails because T REQUIRES A SYSTEM STATE that only exists after a preceding tool runs"**
T's behavior depends on a system state (a created file at a specific path, an active session, a registered hook, an open handle, a pending transaction) that does not exist before the chain runs and that the attacker cannot directly establish. A preceding tool creates this state.
→ Identify the preceding tool that creates the state. Call it A.
→ Proceed to Step 2.

**Answer D — "I am not sure whether B or C clearly applies"**
The composition-necessity claim is not justified by the input. Default to NO chain-level risk.
→ Treat the same as Answer A. Set `is_server_attack_possible = false`. Output JSON.

**CALIBRATION RULES** (apply when picking your answer):

- The discriminator is whether T NEEDS a preceding tool, not whether a preceding tool HAPPENS to be present in the chain. If T can receive equivalent attacker-controlled content as its own parameter directly, the chain is not a composition risk — pick A.
- A tool that simply passes a parameter (path, URL, ID) along to the next tool is a parameter-passer, not a real contributor. Pick A.
- "T consumes external untrusted data (HTTP response, file content)" is a property of T itself, not a contribution from preceding tools. The trailing tool's own ability to consume external data does not make the chain a composition risk. Pick A.
- A preceding tool that writes attacker-supplied content into a location and a later tool that reads that location is NOT a composition risk if T could have received the same attacker content as its own parameter directly. Pick A unless T strictly cannot reach the data any other way.
- Conservatism: if you cannot precisely identify what specific information or state the attacker is missing, pick D (which collapses to A). Do not pick B or C on speculative grounds.

### STEP 2 — VALIDATE THE COMPOSITION RISK (only if you picked Answer B or C)

Confirm all three of:
- A is necessary: removing A from the chain would leave the attacker unable to invoke T successfully.
- The data or state A produces is genuinely beyond the attacker's direct reach (per Rule 5).
- T consumes A's output (data) or A's effect (state) without re-receiving the equivalent from the attacker as a parameter.

If any of these does not hold under a strict reading of the input, downgrade to Answer A: set `is_server_attack_possible = false`, set `exploitability_poc = null`, output JSON.

### STEP 3 — DESIGN THE POC (only if Step 2 confirms the composition risk)

The PoC must demonstrate the composition contribution: it must show how A's output/effect enables T to do something T could not do with attacker-supplied parameters alone.

The PoC must include:
- A step where A is invoked (by attacker or by user, as appropriate) such that A produces the necessary data/state.
- A step where T is invoked, consuming A's output/state, completing the exploit.
- All payload values in PoC steps must use only ALLOWED attacker knowledge (per Rule 5). Do not put attacker-unknown values directly into payloads.

Remove tools from the chain that are not A and not T and that do not contribute. Preserve the order of remaining tools. Set `redundant_steps_removed = true` if any tool was removed; `false` if the original chain is already minimal.

Set `is_server_attack_possible = true`.

### OUTPUT_SCHEMA

{
  "tool_chain": null | [
    { "tool_name": "tool1" },
    { "tool_name": "tool2" }
  ],
  "analysis_results": {
    "is_server_attack_possible": true | false,
    "redundant_steps_removed": true | false,
    "exploitability_poc": null | {
      "steps": [
        {
          "step_idx": 1,
          "actor": "attacker",
          "tool": "<tool name>" | null,
          "expected_behavior": "<=200 chars>",
          "expected_payload": {
            "key": "value"
          }
        }
      ]
    }
  }
}

### FORMAT EXAMPLE (placeholders only — do not match your input to this example)

{
  "tool_chain": [
    { "tool_name": "Tool A" },
    { "tool_name": "Tool T" }
  ],
  "analysis_results": {
    "is_server_attack_possible": true,
    "redundant_steps_removed": false,
    "exploitability_poc": {
      "steps": [
        {
          "step_idx": 1,
          "actor": "attacker",
          "tool": "Tool A",
          "expected_behavior": "Tool A produces data or state that Tool T requires and that the attacker cannot supply directly.",
          "expected_payload": {
            "key": "value"
          }
        },
        {
          "step_idx": 2,
          "actor": "attacker",
          "tool": "Tool T",
          "expected_behavior": "Tool T consumes Tool A's output/state to complete the exploit, which Tool T alone could not achieve with attacker-supplied parameters.",
          "expected_payload": {
            "key": "value"
          }
        }
      ]
    }
  }
}
"""

# Helper function to load tool code data
def load_tool_code_data(server_dir):
    tool_code_file = os.path.join(server_dir, "tool_codes_compact_v1.json")
    with open(tool_code_file, 'r', encoding="utf-8") as f:
        tool_codes = json.load(f)
    return tool_codes


# Function to create user prompt with code snippets
def create_user_prompt(chain, datas):
    # Convert chain to tool name string
    tool_names = " -> ".join(chain)
    tool_codes = datas['m']
    # Get the source code for each tool in the chain
    code_snippets = {}
    for tool_name in chain:
        if tool_name in tool_codes:
            code_snippets[tool_name] = tool_codes[tool_name]
        else:
            code_snippets[tool_name] = ["No code found for this tool."]

    # Construct the user input with tool chain and corresponding code
    user_prompt = {
        "chain": tool_names,
        "code": code_snippets
    }

    return "USER INPUT:\n"+json.dumps(user_prompt, indent=4)


# Function to call OpenRouter API and analyze
def analyze_tool_chain(server_dir, chain, tool_codes):
    # Create user prompt
    user_prompt = create_user_prompt(chain, tool_codes)

    # Prepare the payload
    payload = {
        "model": "x-ai/grok-4-fast",
        "messages": [
            {"role": "system", "content": system_prompt2},
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
            output_dir = os.path.join(server_dir, "output_phase_6_llm")
            os.makedirs(output_dir, exist_ok=True)
            output_filepath = 'chain'
            for item in chain:
                output_filepath += '_'
                output_filepath += item
            output_file = os.path.join(output_dir, output_filepath+'.json')
            result = response.json()
            content = result['choices'][0]['message']['content']
            with open(output_file, 'w') as f:
                json.dump(content, f, indent=4)

            print(f"Analysis complete for chain: {chain}")
            break  # Exit the retry loop if successful
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
            print(f"Error analyzing chain {chain} of json: {e}")
            if attempt < retries - 1:
                print(f"Retrying... (Attempt {attempt + 2}/{retries})")
                time.sleep(5)  # Wait for 5 seconds before retrying
            else:
                print("Max retries reached. Skipping this chain.")
        except requests.exceptions.RequestException as e:
            print(f"Error analyzing chain {chain}: {e}")
            if attempt < retries - 1:
                print(f"Retrying... (Attempt {attempt + 2}/{retries})")
                time.sleep(5)  # Wait for 5 seconds before retrying
            else:
                print("Max retries reached. Skipping this chain.")


# Function to process each MCP server
def process_mcp_server(server_dir):
    # Load vulnerable chains from _phase1_vulnerable_chains.json
    chains_file = os.path.join(server_dir, "_phase1_vulnerable_chains.json")
    with open(chains_file, 'r', encoding="utf-8") as f:
        vulnerable_chains = json.load(f)
        if len(vulnerable_chains) >2000:
            vulnerable_chains = []
    random.seed(0)
    #vulnerable_chains = random.sample(vulnerable_chains,100)
    # Load tool code data
    tool_codes = load_tool_code_data(server_dir)

    # Create a ThreadPoolExecutor to limit the number of threads
    start_time = time.perf_counter()
    with ThreadPoolExecutor(max_workers=10) as executor:  # Limit to 5 concurrent threads
        # Analyze each chain using the thread pool
        futures = [executor.submit(analyze_tool_chain, server_dir, chain_data['chain'], tool_codes) for chain_data in
                   vulnerable_chains]

        # Wait for all threads to complete
        for future in futures:
            future.result()  # This will re-raise any exceptions encountered during the thread execution
    end_time = time.perf_counter()
    print("time useage for one tool:", end_time - start_time, "s")

# Function to process all MCP servers in the input folder.
def process_all_servers(sample_folder):
    # Get all MCP server directories in the input folder.
    server_dirs = [os.path.join(sample_folder, d) for d in os.listdir(sample_folder) if
                   os.path.isdir(os.path.join(sample_folder, d))]
    
    # Process each server
    for server_dir in server_dirs:
        
        print(f"Processing MCP Server: {server_dir}")
        chains_file = os.path.join(server_dir, "_phase1_vulnerable_chains.json")
        if os.path.exists(chains_file):
            process_mcp_server(server_dir)


# Define the sample folder path
sample_folder = "../mcp_servers_repos/"  # Adjust the path as necessary

# Start processing all MCP servers
process_all_servers(sample_folder)

