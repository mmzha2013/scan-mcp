import os
import re
import json
import glob
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from openai import OpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ToolExtractionState:
    """State for the tool extraction agent"""
    project_path: str
    readme_path: Optional[str] = None
    readme_tools: List[str] = None
    grep_tools: List[str] = None
    code_context_tools: List[str] = None
    fallback_tools: List[str] = None
    final_tools: List[str] = None
    current_stage: str = "start"
    confidence_scores: Dict[str, float] = None
    errors: List[str] = None

    def __post_init__(self):
        if self.readme_tools is None:
            self.readme_tools = []
        if self.grep_tools is None:
            self.grep_tools = []
        if self.code_context_tools is None:
            self.code_context_tools = []
        if self.fallback_tools is None:
            self.fallback_tools = []
        if self.final_tools is None:
            self.final_tools = []
        if self.confidence_scores is None:
            self.confidence_scores = {}
        if self.errors is None:
            self.errors = []

class MCPToolExtractionAgent:
    """LangGraph-based agent for extracting tool names from MCP servers"""
    
    def __init__(
        self,
        model: str = None,
        endpoint: str = None,
        api_key: str = None,
    ):
        self.model = model or os.environ.get("OPENAI_MODEL", "deepseek-r1:14b")
        self.endpoint = endpoint or os.environ.get(
            "OPENAI_API_BASE",
            "https://xxxx/openai/v1",
        )
        self.api_key = api_key or os.environ.get("AZURE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise RuntimeError("Set AZURE_API_KEY or OPENAI_API_KEY before running tool extraction.")

        self.client = OpenAI(base_url=self.endpoint, api_key=self.api_key)
        self.graph = self._build_graph()
        
        # Define directories to exclude from analysis
        self.excluded_dirs = {
            'test', 'tests', 'testing', '__tests__',
            '__pycache__', 'node_modules', '.git', '.svn',
            'dist', 'build', 'target', 'out', 'bin', 'obj',
            '.vscode', '.idea', 'coverage', '.nyc_output',
            'tmp', 'temp', 'logs', 'log', 'cache',
            'vendor', 'deps', 'dependencies', 'lib',
            '.next', '.nuxt', 'venv', 'env', '.env',
            'node_modules',
            'docs', 'documentation'
        }

    def _chat(self, messages: List[Dict[str, str]]) -> str:
        """Call the Azure OpenAI-compatible chat completions endpoint."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_completion_tokens=16000,
            temperature=1,
            top_p=1,
        )
        return (response.choices[0].message.content or "").strip()
        
    def _should_exclude_path(self, file_path: str) -> bool:
        """Check if a file path should be excluded from analysis"""
        path_parts = Path(file_path).parts
        
        # Check if any part of the path matches excluded directories
        for part in path_parts:
            if part.lower() in self.excluded_dirs:
                return True
                
        # Check for hidden files/directories (starting with .)
        for part in path_parts:
            if part.startswith('.') and part not in {'.', '..'}:
                return True
                
        return False
    
    def _get_code_files(self, project_path: str, extensions: List[str]) -> List[str]:
        """Get code files while excluding test directories and other unwanted paths"""
        code_files = []
        
        for ext in extensions:
            pattern = os.path.join(project_path, '**', ext)
            all_files = glob.glob(pattern, recursive=True)
            
            # Filter out excluded paths
            for file_path in all_files:
                if not self._should_exclude_path(file_path):
                    code_files.append(file_path)
                else:
                    logger.debug(f"Excluding file: {file_path}")
        
        return code_files
        
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(ToolExtractionState)
        
        # Add nodes
        workflow.add_node("find_readme", self._find_readme_node)
        workflow.add_node("analyze_readme", self._analyze_readme_node)
        workflow.add_node("grep_search", self._grep_search_node)
        workflow.add_node("code_context_analysis", self._code_context_analysis_node)
        workflow.add_node("fallback_analysis", self._fallback_analysis_node)
        workflow.add_node("consolidate_results", self._consolidate_results_node)
        
        # Add edges
        workflow.add_edge("find_readme", "analyze_readme")
        workflow.add_edge("analyze_readme", "grep_search")
        workflow.add_edge("grep_search", "code_context_analysis")
        workflow.add_edge("code_context_analysis", "fallback_analysis")
        workflow.add_edge("fallback_analysis", "consolidate_results")
        workflow.add_edge("consolidate_results", END)
        
        # Set entry point
        workflow.set_entry_point("find_readme")
        
        return workflow.compile()
    
    def _find_readme_node(self, state: ToolExtractionState) -> ToolExtractionState:
        """Find README file in the project"""
        logger.info(f"🔍 Finding README in {state.project_path}")
        
        readme_path = self._find_readme_file(state.project_path)
        state.readme_path = readme_path
        state.current_stage = "readme_found" if readme_path else "no_readme"
        
        if not readme_path:
            state.errors.append("No README file found")
            logger.warning("No README file found")
        else:
            logger.info(f"Found README: {readme_path}")
            
        return state
    
    def _analyze_readme_node(self, state: ToolExtractionState) -> ToolExtractionState:
        """Analyze README file using LLM to extract tool names"""
        logger.info("📖 Analyzing README with LLM")
        
        if not state.readme_path or not os.path.exists(state.readme_path):
            state.errors.append("README file not found or accessible")
            return state
            
        try:
            with open(state.readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                readme_content = f.read()
            
            if not readme_content.strip():
                state.errors.append("README file is empty")
                return state
                
            # Use the existing prompt from the original script
            prompt = self._generate_extract_tool_name_prompt(state.readme_path)
            
            result = self._chat([{"role": "user", "content": prompt}])
            
            # Clean up markdown code blocks
            if result.startswith('```json'):
                result = result[7:]  # Remove ```json
            if result.startswith('```'):
                result = result[3:]   # Remove ```
            if result.endswith('```'):
                result = result[:-3]  # Remove trailing ```
            
            result = result.strip()
            
            # Try to parse JSON result
            try:
                tools = json.loads(result)
                if isinstance(tools, list):
                    state.readme_tools = tools
                    state.confidence_scores["readme"] = 0.9
                    logger.info(f"Extracted {len(tools)} tools from README: {tools}")
                else:
                    state.errors.append("LLM returned non-list result from README")
            except json.JSONDecodeError:
                state.errors.append("Failed to parse JSON from README analysis")
                logger.warning(f"Failed to parse README result: {result}")
                
        except Exception as e:
            state.errors.append(f"Error analyzing README: {str(e)}")
            logger.error(f"Error analyzing README: {e}")
            
        state.current_stage = "readme_analyzed"
        return state
    
    def _grep_search_node(self, state: ToolExtractionState) -> ToolExtractionState:
        """Search for tool patterns in code using grep/regex"""
        logger.info("🔍 Searching for tool patterns in code")
        
        try:
            # Define patterns to search for tool definitions
            patterns = [
                r'name\s*:\s*["\']([^"\']+)["\']',  # name: "tool_name"
                r'defineTool\s*\(\s*{\s*name\s*:\s*["\']([^"\']+)["\']',  # defineTool({ name: "tool_name"
                r'server\.tool\s*\(\s*["\']([^"\']+)["\']',  # server.tool("tool_name"
                r'tools\s*:\s*\[\s*{\s*name\s*:\s*["\']([^"\']+)["\']',  # tools: [{ name: "tool_name"
                r'@tool\s*\(\s*["\']([^"\']+)["\']',  # @tool("tool_name")
                r'register_tool\s*\(\s*["\']([^"\']+)["\']',  # register_tool("tool_name")
            ]
            
            found_tools = set()
            
            # Search in common code files (excluding test directories)
            code_extensions = ['*.js', '*.ts', '*.py', '*.java', '*.go', '*.rs', '*.cpp', '*.c']
            code_files = self._get_code_files(state.project_path, code_extensions)
            
            logger.info(f"Analyzing {len(code_files)} code files (excluding test directories)")
            
            for file_path in code_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            # Filter out common false positives
                            if self._is_valid_tool_name(match):
                                found_tools.add(match)
                except Exception as e:
                    logger.warning(f"Error reading file {file_path}: {e}")
                    continue
            
            state.grep_tools = list(found_tools)
            state.confidence_scores["grep"] = 0.7 if found_tools else 0.0
            logger.info(f"Found {len(found_tools)} tools via grep: {list(found_tools)}")
            
        except Exception as e:
            state.errors.append(f"Error in grep search: {str(e)}")
            logger.error(f"Error in grep search: {e}")
            
        state.current_stage = "grep_completed"
        return state
    
    def _code_context_analysis_node(self, state: ToolExtractionState) -> ToolExtractionState:
        """Analyze code context around potential tool matches using LLM"""
        logger.info("🔬 Analyzing code context with LLM")
        
        if not state.grep_tools:
            logger.info("No tools found via grep, skipping context analysis")
            state.current_stage = "context_skipped"
            return state
            
        try:
            # Find code files that contain the grep matches (excluding test directories)
            code_extensions = ['*.js', '*.ts', '*.py', '*.java', '*.go', '*.rs']
            code_files = self._get_code_files(state.project_path, code_extensions)
            
            context_tools = []
            
            for tool_name in state.grep_tools:
                for file_path in code_files:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                        # Find lines containing the tool name
                        for i, line in enumerate(lines):
                            if tool_name in line:
                                # Get 10 lines of context (5 before, 5 after)
                                start = max(0, i - 5)
                                end = min(len(lines), i + 6)
                                context = ''.join(lines[start:end])
                                
                                # Ask LLM to validate if this is a real tool
                                validation_prompt = f"""
Analyze this code context to determine if '{tool_name}' is a real MCP tool endpoint that users can call.

Code context:
```python
{context}
```

Is '{tool_name}' a callable MCP tool? Respond with only 'YES' or 'NO' and a brief reason.
"""
                                
                                result = self._chat([{"role": "user", "content": validation_prompt}]).upper()
                                if result.startswith('YES'):
                                    context_tools.append(tool_name)
                                    logger.info(f"Validated tool '{tool_name}' via context analysis")
                                    break
                                    
                    except Exception as e:
                        logger.warning(f"Error analyzing context in {file_path}: {e}")
                        continue
                        
            state.code_context_tools = list(set(context_tools))
            state.confidence_scores["context"] = 0.8 if context_tools else 0.0
            logger.info(f"Validated {len(context_tools)} tools via context analysis: {context_tools}")
            
        except Exception as e:
            state.errors.append(f"Error in context analysis: {str(e)}")
            logger.error(f"Error in context analysis: {e}")
            
        state.current_stage = "context_analyzed"
        return state
    
    def _fallback_analysis_node(self, state: ToolExtractionState) -> ToolExtractionState:
        """Fallback LLM analysis of entire codebase"""
        logger.info("🔄 Running fallback LLM analysis on codebase")
        
        try:
            # Collect all code files (excluding test directories)
            code_extensions = ['*.js', '*.ts', '*.py', '*.java', '*.go', '*.rs']
            code_files = self._get_code_files(state.project_path, code_extensions)
            
            logger.info(f"Fallback analysis: analyzing {len(code_files)} code files (excluding test directories)")
            
            # Limit to reasonable size for LLM analysis
            total_size = 0
            selected_files = []
            max_size = 50000  # 50k characters
            
            for file_path in sorted(code_files):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    if total_size + len(content) < max_size:
                        selected_files.append((file_path, content))
                        total_size += len(content)
                    else:
                        break
                except Exception as e:
                    logger.warning(f"Error reading {file_path}: {e}")
                    continue
            
            if not selected_files:
                state.errors.append("No code files found for fallback analysis")
                return state
                
            # Create analysis prompt
            code_content = "\n\n".join([f"// {path}\n{content}" for path, content in selected_files])
            
            fallback_prompt = f"""
Analyze this MCP server codebase to extract ALL tool names that are exposed to clients.

Code files:
{code_content}

Extract tool names that users can call. Look for:
1. Tool registration/definition patterns
2. Function exports that are tools
3. API endpoints that are tools
4. Any callable interfaces

Return ONLY a JSON array of tool names (strings). If none found, return [].
"""
            
            result = self._chat([{"role": "user", "content": fallback_prompt}])
            result = result.replace('```json', '').replace('```', '').strip()
            
            try:
                tools = json.loads(result)
                if isinstance(tools, list):
                    state.fallback_tools = tools
                    state.confidence_scores["fallback"] = 0.6
                    logger.info(f"Found {len(tools)} tools via fallback analysis: {tools}")
                else:
                    state.errors.append("LLM returned non-list result from fallback analysis")
            except json.JSONDecodeError:
                state.errors.append("Failed to parse JSON from fallback analysis")
                logger.warning(f"Failed to parse fallback result: {result}")
                
        except Exception as e:
            state.errors.append(f"Error in fallback analysis: {str(e)}")
            logger.error(f"Error in fallback analysis: {e}")
            
        state.current_stage = "fallback_completed"
        return state
    
    def _consolidate_results_node(self, state: ToolExtractionState) -> ToolExtractionState:
        """Consolidate results from all methods"""
        logger.info("📊 Consolidating results from all methods")
        
        all_tools = set()
        
        # Add tools from different methods with confidence weighting
        if state.readme_tools:
            all_tools.update(state.readme_tools)
            
        if state.code_context_tools:
            all_tools.update(state.code_context_tools)
        elif state.grep_tools:
            # If no context validation, use grep results with lower confidence
            all_tools.update(state.grep_tools)
            
        if state.fallback_tools:
            all_tools.update(state.fallback_tools)
        
        # Remove duplicates and sort
        state.final_tools = sorted(list(all_tools))
        
        # Calculate overall confidence
        if state.confidence_scores:
            state.confidence_scores["overall"] = max(state.confidence_scores.values())
        else:
            state.confidence_scores["overall"] = 0.0
            
        state.current_stage = "completed"
        
        logger.info(f"Final consolidated tools: {state.final_tools}")
        logger.info(f"Confidence scores: {state.confidence_scores}")
        
        return state
    
    def _find_readme_file(self, project_root: str) -> Optional[str]:
        """Find README file in project directory"""
        for dirpath, _, filenames in os.walk(project_root):
            for name in filenames:
                if name.lower().startswith("readme"):
                    return os.path.join(dirpath, name)
        return None
    
    def _generate_extract_tool_name_prompt(self, readme_path: str) -> str:
        """Generate the tool extraction prompt (reused from original script)"""
        if not readme_path or not os.path.exists(readme_path):
            return ""
        with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
            README_TEXT = f.read()
        if not README_TEXT.strip():
            return ""

        header = (
            "You are an expert at parsing MCP server READMEs to extract ONLY the server-exposed tool endpoint names.\n\n"
            "# Goal\n"
            "From the provided README, extract the REAL tool names that the server exposes (i.e., the action endpoints users can call, often shown in a \"Tools\" section with headings like #### `tool_name` or code examples invoking that tool).\n"
            "Return ONLY a machine-readable JSON array of strings (no markdown, no comments, no extra keys). If none, return []. If uncertain, return [].\n\n"
            "# Inclusion Rules (HIGH PRIORITY)\n"
            "A name is a REAL tool if ANY of the following is true:\n"
            "1) It appears as a Markdown heading INSIDE a Tools/工具 section (e.g., #### `tool_name`, ### `tool_name`, or list items with backticked identifiers within that section).\n"
            "2) It is the value of a tool registration/schema field in code blocks (language may vary), e.g.:\n"
            "   - schema: { name: 'tool_name', ... }\n"
            "   - defineTool({ schema: { name: 'tool_name', ... } })\n"
            "   - tools: [{ name: 'tool_name', ... }]\n"
            "   - server.tool('tool_name', ...)\n"
            "3) It is clearly described as \"This tool ...\" / \"该工具 ...\" and formatted as an identifier (snake_case/kebab-case) exposed to clients.\n"
            "4) Invocation Alias / Decorated Name (IMPORTANT): If the README shows a direct invocation token for Claude/user prompts (often under \"Using the Tool/使用方法/Via a prompt\"), such as a standout alias surrounded by symbols (e.g., `_________mcp-easy-copy_________`) or instructions like \"Please use <TOKEN> ... / 请使用 <TOKEN> ...\", treat that TOKEN as a REAL tool **only if** it is clearly presented as how to invoke this server's callable action(s).\n"
            "   Heuristics for TOKEN:\n"
            "   - Typically appears in fenced code blocks or inline code on lines instructing to use/call/invoke/请使用.\n"
            "   - TOKEN characters: letters, numbers, hyphen, underscore; optional decorators (e.g., 3+ underscores on BOTH sides).\n\n"
            "# Conflict Resolution Priority (STRICT)\n"
            "When multiple variants of the same base name appear (e.g., the plain package/server name vs. a decorated invocation alias):\n"
            "A) If a decorated invocation alias exists (e.g., `_________mcp-easy-copy_________`), **RETURN ONLY THE DECORATED ALIAS EXACTLY AS SHOWN**. Do NOT normalize or strip underscores.\n"
            "B) If NO decorated alias exists but a registered/schema name exists, return the registered/schema name.\n"
            "C) If only a plain package/server name appears and it is NOT explicitly presented as a callable endpoint, **EXCLUDE IT**.\n"
            "Example to enforce: If both `mcp-easy-copy` and `_________mcp-easy-copy_________` appear, the ONLY correct output is [\"_________mcp-easy-copy_________\"] — never [\"mcp-easy-copy\"].\n\n"
            "# Exclusion Rules (STRICT)\n"
            "Exclude anything that is NOT a callable endpoint:\n"
            "- Installation/build tooling: npm, npx, yarn, pnpm, bun, gradle, maven, make, gcc, clang, cmake, docker, playwright (framework), browsers, node, python, java, etc.\n"
            "- Libraries/SDKs/APIs/packages/modules unless explicitly exposed as a callable tool endpoint.\n"
            "- File paths, commands, flags, environment variables, section titles, or parameter names (e.g., \"name\", \"selector\", \"script\"), or example values.\n"
            "- Package/repo/server names that appear only in badges, install/config examples, or prose and are NOT shown as callable endpoints.\n\n"
            "# Heuristics\n"
            "- Prefer items under a section explicitly titled \"Tools\" / \"工具\".\n"
            "- Tool identifiers often look like: browser_click, browser_fill, foo-bar, http_request, etc.\n"
            "- For invocation tokens, accept decorated forms EXACTLY AS SHOWN when the README instructs users to \"use/call/invoke/请使用\" that token.\n"
            "- Ignore JSON fields that are clearly parameters of a tool (e.g., {\"name\":\"screenshot-name\"} is a parameter, not a tool).\n"
            "- Preserve source order; de-duplicate exact matches. If duplicates share the same base, keep the longest token (decorated) and drop the shorter (plain) form.\n\n"
            "# Output\n"
            "- Output EXACTLY one JSON array of strings.\n"
            "- No prose, no markdown code fences, no trailing commas.\n"
            "- If no valid tools are found, output []. If uncertain, output [].\n\n"
            "Now parse the README below and produce ONLY the JSON array of tool names:\n\n"
        )
        return header + "<README>\n" + README_TEXT + "\n</README>\n"
    
    def _is_valid_tool_name(self, name: str) -> bool:
        """Check if a name looks like a valid tool name"""
        if not name or len(name) < 2:
            return False
            
        # Common false positives to exclude
        false_positives = {
            'name', 'type', 'description', 'input', 'output', 'schema', 'properties',
            'required', 'optional', 'default', 'value', 'key', 'id', 'title',
            'version', 'author', 'license', 'main', 'scripts', 'dependencies',
            'devDependencies', 'repository', 'bugs', 'homepage', 'keywords'
        }
        
        if name.lower() in false_positives:
            return False
            
        # Should contain letters and possibly numbers, hyphens, underscores
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', name):
            return False
            
        return True
    
    async def extract_tools(self, project_path: str) -> ToolExtractionState:
        """Extract tools from a project using the LangGraph agent"""
        initial_state = ToolExtractionState(project_path=project_path)
        
        # Run the graph
        result = await self.graph.ainvoke(initial_state)
        # LangGraph returns a dict, so we need to convert it back to our state object
        if isinstance(result, dict):
            return ToolExtractionState(**result)
        return result
    
    def extract_tools_sync(self, project_path: str) -> ToolExtractionState:
        """Synchronous version of extract_tools"""
        return asyncio.run(self.extract_tools(project_path))

def main():
    """Example usage of the MCP Tool Extraction Agent"""
    # Configuration
    BASE_DIR = "../mcp_servers_repos"
    
    # Initialize agent
    agent = MCPToolExtractionAgent()
    
    # Process all projects
    projects = [os.path.join(BASE_DIR, d) for d in os.listdir(BASE_DIR) 
                if os.path.isdir(os.path.join(BASE_DIR, d))]
    
    results = {}
    
    for project_path in projects:
        print(f"\n🔍 Processing {project_path}")
        try:
            result = agent.extract_tools_sync(project_path)
            results[project_path] = result
            
            # Save results
            output_path = os.path.join(project_path, "tool_extraction_results.json")
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'final_tools': result.final_tools,
                    'confidence_scores': result.confidence_scores,
                    'errors': result.errors,
                    'stages': {
                        'readme_tools': result.readme_tools,
                        'grep_tools': result.grep_tools,
                        'code_context_tools': result.code_context_tools,
                        'fallback_tools': result.fallback_tools
                    }
                }, f, indent=2)
            
            print(f"✅ Extracted {len(result.final_tools)} tools: {result.final_tools}")
            print(f"📊 Confidence: {result.confidence_scores.get('overall', 0):.2f}")
            
        except Exception as e:
            print(f"❌ Error processing {project_path}: {e}")
            results[project_path] = None
    
    # Summary
    print(f"\n📈 Summary:")
    total_tools = sum(len(r.final_tools) if r else 0 for r in results.values())
    successful_projects = sum(1 for r in results.values() if r is not None)
    print(f"Processed {successful_projects}/{len(projects)} projects successfully")
    print(f"Total tools extracted: {total_tools}")

if __name__ == "__main__":
    main()
