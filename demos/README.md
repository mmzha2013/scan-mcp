# Video Demos

This directory contains demonstration videos illustrating the vulnerabilities analyzed in our paper.

## Contents

### 1. Arbitrary Command Execution (Single-Tool Vulnerability)

**File:** `1_Arbitrary_Command_Execution_Single_Tool_Vulnerability.mp4`

This demo shows a **single-tool vulnerability** in which an attacker abuses an MCP tool capable of executing arbitrary system commands. The video demonstrates how the vulnerable tool can be invoked to perform unintended command execution.

---

### 2. Write–Execute Chain (Tool-Chain Vulnerability)

**File:** `2_Write_Execute_Chain_Tool-Chain_Vulnerability.mp4`

This demo illustrates a **tool-chain vulnerability** involving a write–execute attack chain. The first tool writes attacker-controlled content to the local system, and a subsequent tool executes the generated file, resulting in arbitrary code execution through the interaction of multiple tools.

---

### 3. Browse–Click–Upload Chain (Tool-Chain Vulnerability)

**File:** `3_Browse_Click_Upload_Chain_Tool-Chain_Vulnerability.mp4`

This demo presents a **tool-chain vulnerability** consisting of a browse–click–upload attack chain. By combining multiple MCP tools, the attacker induces the agent to visit a malicious webpage, interact with attacker-controlled content, and ultimately upload sensitive victim data to an attacker-controlled website.

---

## Notes

These videos are provided as supplementary material for the paper and demonstrate representative examples of the vulnerabilities detected by our analysis framework. The demonstrations are intended solely for research and evaluation purposes.

