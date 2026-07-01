#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analyze MCP projects (multiprocess) - Full AST-based Implementation
--------------------------------------------------------------------
- This script is a complete refactor of the original, replacing all regex-based
  parsing with a robust AST (Abstract Syntax Tree) based approach using tree-sitter.
- It provides significantly higher accuracy, stability, and robustness in analyzing
  source code across multiple languages.
"""

from __future__ import annotations
import os, re, json, sys, logging, multiprocessing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from concurrent.futures import ProcessPoolExecutor, as_completed
import traceback  # Import traceback for detailed error logging

# --- FINAL SIMPLIFICATION ---
# Since we have confirmed a modern tree-sitter version is installed,
# we can now remove the complex fallback logic and use the modern imports directly.
# This is cleaner and avoids the previous error.
import tree_sitter_python as tspython
import tree_sitter_go as gopython
import tree_sitter_php as phpython
import tree_sitter_java as javapython
import tree_sitter_c_sharp as cspython
import tree_sitter_javascript as jspython
import tree_sitter_typescript as typython
import tree_sitter_kotlin as kpython
import tree_sitter_ruby as rbpython
import tree_sitter_rust as rtpython
import tree_sitter_swift as swpython
from tree_sitter import Language, Parser, Query

# --- Logging Setup ---
# Configure root logger for basic info to stdout
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    stream=sys.stdout)  # Explicitly use stdout

# Get the root logger instance
root_logger = logging.getLogger()


# --- FIXED with enhanced error logging ---
def _make_query(lang, qsrc: str):
    """Create a tree-sitter query and re-raise compilation errors with context."""
    from tree_sitter import Query
    try:
        # Use the modern lang.query(qsrc) API required by tree-sitter 0.25.x.
        return Query(lang, qsrc)
    except Exception as e:
        # Log the error here before re-raising it
        # Use root_logger because this might be called before per-project logger is set up
        root_logger.error(
            f"Failed to compile query. Language: {getattr(lang, 'name', 'unknown')}, Error: {e}\nQuery Source (first 200 chars):\n{qsrc[:200]}\n---")
        raise  # Re-raise the exception to be caught by the caller


# ====================== Global Configuration ======================

BASE_CODE_DIR = Path("../mcp_servers_repos")
MAX_WORKERS = 2  
MAX_DEPTH = 20

# ====================== Language & AST Configuration ======================
LANGUAGE_MAPPING = {
    ".py": {"name": "python", "repo": "tree-sitter-python"},
    ".js": {"name": "javascript", "repo": "tree-sitter-javascript"},
    ".jsx": {"name": "javascript", "repo": "tree-sitter-javascript"},
    ".mjs": {"name": "javascript", "repo": "tree-sitter-javascript"},
    ".cjs": {"name": "javascript", "repo": "tree-sitter-javascript"},
    ".ts": {"name": "typescript", "repo": "tree-sitter-typescript/typescript"},
    ".tsx": {"name": "tsx", "repo": "tree-sitter-typescript/tsx"},
    ".go": {"name": "go", "repo": "tree-sitter-go"},
    ".php": {"name": "php", "repo": "tree-sitter-php/php"},
    ".java": {"name": "java", "repo": "tree-sitter-java"},
    ".cs": {"name": "c_sharp", "repo": "tree-sitter-c-sharp"},
    ".rb": {"name": "ruby", "repo": "tree-sitter-ruby"},
    ".rs": {"name": "rust", "repo": "tree-sitter-rust"},
    ".swift": {"name": "swift", "repo": "tree-sitter-swift"},
    ".kt": {"name": "kotlin", "repo": "kotlin-tree-sitter"},
}
ALL_EXTS = tuple(LANGUAGE_MAPPING.keys())
# ==== Function-like node types that we treat as "definitions" per language ====
FUNCTION_LIKE_NODE_TYPES = {
    # Fix 2.
    # In the 0.25.x grammar, async def is also parsed as function_definition.
    "python": {"function_definition"},
    "javascript": {
        "function_declaration", "method_definition",
        "arrow_function", "function_expression"  # Added function_expression tentatively
    },
    "typescript": {
        "function_declaration", "method_definition",
        "arrow_function", "function_expression"  # Added function_expression tentatively
    },
    "tsx": {
        "function_declaration", "method_definition",
        "arrow_function", "function_expression"  # Added function_expression tentatively
    },
    "java": {"method_declaration", "constructor_declaration"},
    "c_sharp": {"method_declaration", "constructor_declaration"},

    # Go: include method_declaration for receiver methods.
    "go": {"function_declaration", "method_declaration"},

    # PHP: include method_declaration for class methods.
    "php": {"function_definition", "method_declaration"},

    # Ruby: include singleton_method for class/module methods.
    "ruby": {"method", "singleton_method"},

    "rust": {"function_item"},
    "swift": {"function_declaration", "initializer_declaration"},
    "kotlin": {"function_declaration"},
}
# ==== Tree-sitter queries for collecting definitions & calls ====
QUERIES = {
    "python": {
        # Fix: use a one-line ordinary string to avoid possible multiline issues.
        "functions": "(function_definition name: (identifier) @name) @definition",
        "calls": r"(call function: _ @callee) @call",
    },
    "javascript": {
    # Fix: remove invalid '(function)' node references.
    # Fix: remove public_field_definition because it is TypeScript-only and absent from the JS grammar.
    "functions": r"""
        (function_declaration name: (identifier) @name) @definition
        (method_definition name: (property_identifier) @name) @definition
        (variable_declarator name: (identifier) @name
            value: [(arrow_function)] ;; Removed (function)
        ) @definition
        (pair key: (property_identifier) @name
            value: [(arrow_function)] ;; Removed (function)
        ) @definition
        ;; Check if function_expression is the correct node for assigned functions
        (variable_declarator name: (identifier) @name value: (function_expression name: (identifier)? @func_expr_name)) @definition
        (pair key: (property_identifier) @name value: (function_expression name: (identifier)? @func_expr_name)) @definition
    """,
    "calls": r"(call_expression function: _ @callee) @call",
    },
    "typescript": {
        # Fix: remove invalid '(function)' node references.
        "functions": r"""
            (function_declaration name: (identifier) @name) @definition
            (method_definition name: (property_identifier) @name) @definition
            (variable_declarator name: (identifier) @name
                value: [(arrow_function)] ;; Removed (function)
            ) @definition
            (pair key: (property_identifier) @name
                value: [(arrow_function)] ;; Removed (function)
            ) @definition
            ;; Check if function_expression is the correct node for assigned functions
            (variable_declarator name: (identifier) @name value: (function_expression name: (identifier)? @func_expr_name)) @definition
            (pair key: (property_identifier) @name value: (function_expression name: (identifier)? @func_expr_name)) @definition

            (export_statement
                declaration: [
                    (function_declaration name: (identifier) @name)
                    (lexical_declaration (variable_declarator name: (identifier) @name))
                ]
            ) @definition

            (public_field_definition
                name: (property_identifier) @name
                value: [(arrow_function)] ;; Removed (function)
            ) @definition
             (public_field_definition
                name: (property_identifier) @name
                value: (function_expression name: (identifier)? @func_expr_name)
            ) @definition
        """,
        "calls": r"(call_expression function: _ @callee) @call",
    },
}
# Reuse TypeScript handling for TSX.
QUERIES["tsx"] = QUERIES["typescript"]

QUERIES.update({
    "java": {
        "functions": r"""
            (method_declaration name: (identifier) @name) @definition
            (constructor_declaration name: (identifier) @name) @definition
        """,
        # Capture ordinary method calls and constructor creation.
        "calls": r"""
            (method_invocation name: _ @callee) @call
            (object_creation_expression) @call
        """,
    },

    "c_sharp": {
        "functions": r"""
            (method_declaration name: (identifier) @name) @definition
            (constructor_declaration name: (identifier) @name) @definition
        """,
        # Ordinary calls and object creation through constructors.
        "calls": r"""
            (invocation_expression function: _ @callee) @call
            (object_creation_expression) @call
        """,
    },

    "go": {
        "functions": r"""
            (function_declaration name: (identifier) @name) @definition
            (method_declaration name: (field_identifier) @name) @definition
        """,
        "calls": r"(call_expression function: _ @callee) @call",
    },

    "php": {
        "functions": r"""
            (function_definition name: (name) @name) @definition
            (method_declaration name: (name) @name) @definition
        """,
        # Ordinary functions, object methods, and static methods.
        "calls": r"""
            [
              (function_call_expression)
              (member_call_expression)
              (scoped_call_expression)
            ] @call
        """,
    },

    "ruby": {
        # Ordinary methods and singleton methods such as class << self or def self.foo.
        "functions": r"""
            (method name: (identifier) @name) @definition
            (singleton_method name: (identifier) @name) @definition
        """,
        "calls": r"(call) @call",
    },

    "rust": {
        "functions": r"""
            (function_item name: (identifier) @name) @definition
        """,
        # Add method_call_expression for obj.method(...).
        "calls": r"""
            (call_expression function: _ @callee) @call
            (method_call_expression method: (identifier) @callee) @call
        """,
    },

    "swift": {
        "functions": r"""
            (function_declaration name: (simple_identifier) @name) @definition
            (initializer_declaration) @definition
        """,
        # Swift generally represents method and function calls as function_call_expression.
        "calls": r"(function_call_expression) @call",
    },

    "kotlin": {
        "functions": r"""
            (function_declaration name: (simple_identifier) @name) @definition
        """,
        # Calls and constructor invocations.
        "calls": r"""
            (call_expression) @call
            (constructor_invocation) @call
        """,
    },
})

HINT_NAME_REGEXES = {
    # py, python, Python
    "python": re.compile(r"def\s+([a-zA-Z_][a-zA-Z0-9_]+)"),

    # js, javascript, JavaScript
    "javascript": re.compile( r"(?:function\s+|^\s*(?:#?\s*)(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+|\*\s*)?)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(" ),

    # ts, typescript, TypeScript
    "typescript": re.compile( r"(?:function\s+|^\s*(?:#?\s*)(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+|\*\s*)?)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(" ),

    # tsx, TSX
    "tsx": re.compile( r"(?:function\s+|^\s*(?:#?\s*)(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+|\*\s*)?)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(" ),

    # rb, ruby, Ruby
    "ruby": re.compile(r"def\s+([a-zA-Z_][a-zA-Z0-9_]+)"),

    # rs, rust, Rust
    "rust": re.compile(r"fn\s+([a-zA-Z_][a-zA-Z0-9_]+)"),

    # cs, c#, csharp, c_sharp, CSharp
    # Match [Modifiers] ReturnType FuncName(.
    "c_sharp": re.compile(r"[a-zA-Z0-9_<>\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\("),

    # go, Go
    # Match func (recv) FuncName.
    "go": re.compile(r"func\s+(?:(?:\([^\)]*\)\s*)?)([a-zA-Z_][a-zA-Z0-9_]+)"),

    # java, Java
    # Match [Modifiers] ReturnType FuncName(.
    "java": re.compile(r"[a-zA-Z0-9_<>\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\("),

    # php, PHP
    "php": re.compile(r"function\s+([a-zA-Z_][a-zA-Z0-9_]+)"),

    # swift, Swift
    "swift": re.compile(r"func\s+([a-zA-Z_][a-zA-Z0-9_]+)"),

    # kotlin, Kotlin
    "kotlin": re.compile(r"fun\s+([a-zA-Z_][a-zA-Z0-9_]+)"),
}


# ====================== Utility Functions ======================
# Use root logger for utility functions or get logger instance if needed
# def log_debug(*a, **k):
#     if TRACE_LOG: print(*a, file=sys.stderr, **k) # Keep if still needed


def extract_hint_name(snippet: str, lang_name: str) -> Optional[str]:
    """Extract the most useful symbol name from a hint snippet."""
    logger = logging.getLogger(__name__)  # Use module logger
    if not snippet or not lang_name:
        return None

    regex = HINT_NAME_REGEXES.get(lang_name)
    if not regex:
        logger.warning(f"No regex configured for lang: {lang_name}")
        return None

    first_lines = "\n".join(snippet.splitlines()[:5])
    match = regex.search(first_lines)
    if match:
        return match.group(1)
    return None


def read_text(p: Path) -> str:
    logger = logging.getLogger(__name__)  # Use module logger
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.error(f"Failed to read file {p}: {e}", exc_info=True)  # Log exception info
        return ""


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root).as_posix())
    except Exception:
        return p.as_posix()


def abs_str(p: Path) -> str:
    try:
        return str(p.resolve())
    except Exception:
        return str(p)


def get_node_text(node, text: str) -> str:
    # Add check for None node
    if node is None:
        return ""
    return text[node.start_byte:node.end_byte]


# ====================== Data Structures ======================
@dataclass
class CallSite:
    callee_text: str;
    line: int;
    start_byte: int;
    end_byte: int
    arg_text: str = "";
    call_src: str = "";
    sink: bool = False


@dataclass
class FuncEntry:
    func_id: str;
    file_rel: str;
    file_abs: str;
    name: str;
    line: int
    start_byte: int;
    end_byte: int;
    code: str = ""
    params: List[str] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    # ---- NEW ----
    lang: str = ""
    class_name: str = ""


def mk_func_id(path_rel: str, name: str, line: int) -> str:
    return f"{path_rel}::{name}@{line}"


# ====================== Tree-sitter Manager ======================
class TreeSitterManager:
    """
    Handles loading and querying tree-sitter grammars directly
    from pre-installed language packages (e.g., tree_sitter_python).
    """

    def __init__(self):
        """Initializes the manager by loading all imported grammars."""
        self.logger = logging.getLogger(self.__class__.__name__)  # Use class name for logger
        self.logger.info("Initializing TreeSitterManager...")
        self.languages: Dict[str, Language] = {}
        self.parsers: Dict[str, Parser] = {}
        self._load_grammars()

    def _load_grammars(self):
        """
        Load grammars directly from the pre-installed tree-sitter language packages
        """
        self.logger.info("Attempting to load grammars from pre-installed packages...")
        lang_obj_map: Dict[str, Language] = {}
        # --- Load all language packages ---
        # (Error handling included for each)
        try:
            lang_obj_map["python"] = Language(tspython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'python': {e}")
        try:
            lang_obj_map["go"] = Language(gopython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'go': {e}")
        try:
            lang_obj_map["java"] = Language(javapython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'java': {e}")
        try:
            lang_obj_map["c_sharp"] = Language(cspython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'c_sharp': {e}")
        try:
            lang_obj_map["javascript"] = Language(jspython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'javascript': {e}")
        try:
            lang_obj_map["kotlin"] = Language(kpython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'kotlin': {e}")
        try:
            lang_obj_map["ruby"] = Language(rbpython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'ruby': {e}")
        try:
            lang_obj_map["rust"] = Language(rtpython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'rust': {e}")
        try:
            lang_obj_map["swift"] = Language(swpython.language())
        except Exception as e:
            self.logger.warning(f"Failed to load 'swift': {e}")
        try:
            import tree_sitter_php
            lang_obj_map["php"] = Language(tree_sitter_php.language_php())
        except Exception as e:
            self.logger.warning(f"Failed to load 'php' (special case): {e}")
        try:
            import tree_sitter_typescript
            lang_obj_map["typescript"] = Language(tree_sitter_typescript.language_typescript())
        except Exception as e:
            self.logger.warning(f"Failed to load 'typescript' (special case): {e}")
        try:
            import tree_sitter_typescript
            lang_obj_map["tsx"] = Language(tree_sitter_typescript.language_tsx())
        except Exception as e:
            self.logger.warning(f"Failed to load 'tsx' (special case): {e}")

        # --- Build parsers ---
        loaded_count = 0
        unique_lang_names = set(m["name"] for m in LANGUAGE_MAPPING.values())
        for lang_name in unique_lang_names:
            language = lang_obj_map.get(lang_name)
            if language:
                try:
                    parser = Parser(language)
                    self.languages[lang_name] = language
                    self.parsers[lang_name] = parser
                    self.logger.info(f"Successfully loaded grammar and parser for '{lang_name}'.")
                    loaded_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to create parser for '{lang_name}': {e}", exc_info=True)
            else:
                self.logger.warning(f"Language object for '{lang_name}' was not available. Skipping.")

        if loaded_count == 0:
            self.logger.critical("Failed to load ANY grammars. Aborting.")
            raise RuntimeError("Failed to load ANY grammars.")
        self.logger.info(f"Grammar loading complete. Loaded {loaded_count} languages.")

    def _ensure_alias_map(self):
        if not hasattr(self, "_ALIAS"):
            self._ALIAS = {
                'py': 'python', 'python': 'python', 'Python': 'python',
                'js': 'javascript', 'javascript': 'javascript', 'JavaScript': 'javascript',
                'ts': 'typescript', 'typescript': 'typescript', 'TypeScript': 'typescript',
                'tsx': 'tsx', 'TSX': 'tsx',
                'rb': 'ruby', 'ruby': 'ruby', 'Ruby': 'ruby',
                'rs': 'rust', 'rust': 'rust', 'Rust': 'rust',
                'cs': 'c_sharp', 'c#': 'c_sharp', 'csharp': 'c_sharp', 'c_sharp': 'c_sharp', 'CSharp': 'c_sharp',
                'go': 'go', 'Go': 'go',
                'java': 'java', 'Java': 'java',
                'php': 'php', 'PHP': 'php',
                'swift': 'swift', 'Swift': 'swift',
                'kotlin': 'kotlin', 'Kotlin': 'kotlin'
            }

    def _canon(self, name: str) -> str:
        self._ensure_alias_map()
        return self._ALIAS.get((name or '').strip(), (name or '').strip().lower())

    def is_supported(self, lang_name: str) -> bool:
        lname = self._canon(lang_name)
        return lname in self.parsers

    def parse(self, lang_name: str, text: str):
        lname = self._canon(lang_name)
        parser = self.parsers.get(lname)
        if parser is None:
            self.logger.error(f"Parser not available for language: {lang_name} (canonical: {lname})")
            raise RuntimeError(f"Language parser not available: {lang_name}")
        self.logger.debug(f"Parsing content for language '{lname}'...")
        try:
            tree = parser.parse(bytes(text, 'utf-8', errors='ignore'))
            self.logger.debug(f"Parsing successful for '{lname}'. Root node: {tree.root_node.type}")
            return tree
        except Exception as e:
            self.logger.error(f"Error parsing content for '{lname}': {e}", exc_info=True)
            raise

    def query_old(self, lang_name: str, node_or_tree, kind: str):
        lname = self._canon(lang_name)
        lang = self.languages.get(lname)
        qmap = QUERIES.get(lname, {})
        qsrc = qmap.get(kind)
        if not lang or not qsrc:
            self.logger.debug(f"No query configured for lang '{lname}', kind '{kind}'.")
            return []

        self.logger.debug(f"Attempting query for lang '{lname}', kind '{kind}'...")
        try:
            q = _make_query(lang, qsrc)
            root_logger.warning(
                f"[DIAG] _make_query returned q={q!r}, type={type(q).__name__}, module={type(q).__module__}")
        except Exception as _make_exc:
            root_logger.error(f"[DIAG] _make_query raised: {_make_exc!r}")
            return []  # Return empty list if compilation failed

        root = getattr(node_or_tree, 'root_node', None) or node_or_tree
        self.logger.debug(f"Executing query on node: {root.type} ({root.start_point} - {root.end_point})")

        try:
            # Fix: handle captures attribute errors and return-type differences.
            if hasattr(q, 'captures'):
                # .captures() can return List[Tuple[Node, str]] OR Dict[str, List[Node]]
                captures_result = q.captures(root)
                self.logger.debug(
                    f"Query executed successfully using '.captures()'. Result type: {type(captures_result)}. Found {len(captures_result)} items/keys.")
                return captures_result  # Return whatever it gives
            else:
                # This case might indicate an older/incompatible Query object style returned
                # for certain languages (like observed with Rust). Log a warning.
                self.logger.warning(f"Query object for lang '{lname}' lacks '.captures()' method. "
                                    f"Type: {type(q)}. Query execution might be incomplete for this language.")
                # Attempt to use QueryCursor as a fallback (might fail if QueryCursor isn't available)
                try:
                    from tree_sitter import QueryCursor  # Import locally for fallback
                    cursor = QueryCursor(q)
                    #root_logger.warning(f"[DIAG] tree_sitter module file: {_ts_diag.__file__}")
                    root_logger.warning(f"[DIAG] q type: {type(q)}, q repr: {q!r}")
                    root_logger.warning(f"[DIAG] root type: {root.type}, root has {len(root.children)} children")
                    root_logger.warning(f"[DIAG] cursor type: {type(cursor)}")
                    captures_result = cursor.captures(root)
                    root_logger.warning(
                        f"[DIAG] captures_result type: {type(captures_result)}, value: {str(captures_result)[:300]!r}")
                    self.logger.warning(
                        f"Fallback to QueryCursor successful. Result type: {type(captures_result)}. Found {len(captures_result)} items.")
                    return captures_result
                except ImportError:
                    self.logger.error("QueryCursor not available for fallback.")
                    return []
                except Exception as qc_e:
                    self.logger.error(f"Error using QueryCursor fallback: {qc_e}", exc_info=True)
                    return []

        except AttributeError as ae:
            # Should be caught by hasattr check, but as a safeguard
            self.logger.error(
                f"AttributeError during query execution for lang {lname}, kind {kind}: {ae}. Query obj type: {type(q)}",
                exc_info=True)
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error during query execution for lang {lname}, kind {kind}: {e}",
                              exc_info=True)
            return []

    def query(self, lang_name: str, node_or_tree, kind: str):
        lname = self._canon(lang_name)
        lang = self.languages.get(lname)
        qmap = QUERIES.get(lname, {})
        qsrc = qmap.get(kind)
        if not lang or not qsrc:
            self.logger.debug(f"No query configured for lang '{lname}', kind '{kind}'.")
            return []

        self.logger.debug(f"Attempting query for lang '{lname}', kind '{kind}'...")
        try:
            q = _make_query(lang, qsrc)
            root_logger.warning(
            f"[DIAG] _make_query returned q={q!r}, type={type(q).__name__}, module={type(q).__module__}")
        except Exception as _make_exc:
            root_logger.error(f"[DIAG] _make_query raised: {_make_exc!r}")
            return []

        root = getattr(node_or_tree, 'root_node', None) or node_or_tree
        self.logger.debug(f"Executing query on node: {root.type} ({root.start_point} - {root.end_point})")

        # tree-sitter 0.25.x requires QueryCursor; Query no longer exposes .captures().
        try:
            from tree_sitter import QueryCursor
            cursor = QueryCursor(q)
            #root_logger.warning(f"[DIAG] tree_sitter module file: {_ts_diag.__file__}")
            root_logger.warning(f"[DIAG] q type: {type(q)}, q repr: {q!r}")
            root_logger.warning(f"[DIAG] root type: {root.type}, root has {len(root.children)} children")
            root_logger.warning(f"[DIAG] cursor type: {type(cursor)}")
            captures_result = cursor.captures(root)
            root_logger.warning(
                f"[DIAG] captures_result type: {type(captures_result)}, value: {str(captures_result)[:300]!r}")
            if isinstance(captures_result, dict):
                self.logger.debug(
                    f"QueryCursor.captures() returned dict with keys {list(captures_result.keys())}, "
                    f"total nodes={sum(len(v) for v in captures_result.values())}.")
            elif isinstance(captures_result, list):
                self.logger.debug(f"QueryCursor.captures() returned list with {len(captures_result)} items.")
            return captures_result
        except ImportError:
            # Fallback for very old versions where Query may still expose .captures().
            if hasattr(q, 'captures'):
                try:
                    return q.captures(root)
                except Exception as e:
                    self.logger.error(f"q.captures fallback failed for lang {lname}: {e}", exc_info=True)
                    return []
            self.logger.error("Neither QueryCursor nor Query.captures available.")
            return []
        except Exception as e:
            self.logger.error(f"QueryCursor.captures failed for lang {lname}, kind {kind}: {e}", exc_info=True)
            return []


# ====================== AST-based Function and Call Extraction ======================
def build_function_index(project_root: Path,
                         files: Optional[List[Path]],
                         ts_manager,
                         logger: logging.Logger) -> Dict[str, FuncEntry]:  # Pass logger
    """
    Builds an index of function definitions from source files using tree-sitter.
    """
    index: Dict[str, FuncEntry] = {}
    exts = set(LANGUAGE_MAPPING.keys())

    to_scan: List[Path]
    if files:
        logger.info(f"Scanning {len(files)} provided files...")
        to_scan = [p for p in files if isinstance(p, Path)]
    else:
        logger.info(f"No specific files provided, scanning all under {project_root}...")
        to_scan = list(project_root.rglob("*"))
        logger.info(f"Found {len(to_scan)} potential items.")

    processed_files = 0
    skipped_ext = 0
    skipped_read = 0
    skipped_unsupported_lang = 0
    skipped_parse_fail = 0
    total_funcs_indexed = 0

    for file_path in to_scan:
        logger.debug(f"Processing item: {file_path}")
        if not file_path.is_file():
            logger.debug("Skipping non-file.")
            continue
        ext = file_path.suffix.lower()
        if ext not in exts:
            # logger.debug(f"Skipping file with unsupported extension: {ext}") # Too verbose
            skipped_ext += 1
            continue

        text = read_text(file_path)  # read_text handles its own logging
        if not text:
            # logger.warning(f"Skipping empty file: {file_path}") # Logged by read_text if error
            skipped_read += 1
            continue

        lang_name = LANGUAGE_MAPPING[ext]["name"]
        if not ts_manager.is_supported(lang_name):
            logger.warning(f"Skipping file, language '{lang_name}' parser not loaded/supported: {file_path}")
            skipped_unsupported_lang += 1
            continue

        try:
            tree = ts_manager.parse(lang_name, text)  # parse handles its logging
        except Exception:
            # Error logged by ts_manager.parse
            skipped_parse_fail += 1
            continue  # Skip file if parsing fails

        try:
            relp = str(file_path.relative_to(project_root)).replace("\\", "/")
        except Exception:
            relp = file_path.name
        absp = abs_str(file_path)
        logger.debug(f"File '{relp}' parsed successfully.")

        # --- Helpers for class/receiver name extraction ---
        def _enclosing_class_name_generic(node) -> str:
            # ... (implementation unchanged) ...
            CLASS_LIKE = {
                "class_declaration", "class", "class_body", "class_definition",
                "interface_declaration", "enum_declaration",
                "struct_declaration", "struct_specifier",
                "impl_item", "impl_block", "implementation",
                "scoped_class_specifier",
                "module_declaration", "namespace_declaration", "module", "namespace"
            }
            NAME_NODES = {"identifier", "type_identifier", "name", "simple_identifier", "property_identifier"}
            cur = node
            while cur is not None:
                if cur.type in CLASS_LIKE:
                    for ch in cur.children or []:
                        if ch.type in NAME_NODES:
                            val = get_node_text(ch, text).strip()
                            if val:
                                return val
                cur = cur.parent
            return ""

        def _extract_go_receiver_type(node) -> str:
            # ... (implementation unchanged) ...
            try:
                recv = None
                for ch in node.children or []:
                    if ch.type == "receiver":
                        recv = ch
                        break
                if recv is None:
                    recv = node
                best = ""
                stack = [recv]
                while stack:
                    n = stack.pop()
                    for c in reversed(n.children or []):
                        stack.append(c)
                    if n.type in ("type_identifier", "qualified_type", "pointer_type"):
                        val = get_node_text(n, text)
                        if val:
                            val = re.split(r"[*&\[\]\s]", val)[-1].strip()
                            if val:
                                best = val
                return best
            except Exception as e:
                logger.warning(f"Error extracting Go receiver type in {relp}: {e}")
                return ""

        # --- End Helpers ---

        # === Execute tree-sitter query for function definitions ===
        func_captures_result = []  # Use a neutral name for the result
        try:
            logger.debug(f"Querying 'functions' in '{relp}'...")
            # ts_manager.query now handles compile/execute errors internally and logs them
            # It can return List or Dict
            func_captures_result = ts_manager.query(lang_name, tree.root_node, "functions")
            logger.debug(
                f"Raw query result type: {type(func_captures_result)}. Length/Keys: {len(func_captures_result) if isinstance(func_captures_result, (list, dict)) else 'N/A'}.")

        except Exception as e:
            # Catch unexpected errors from the query method itself
            logger.error(f"Unexpected error calling ts_manager.query for 'functions' in {relp}: {e}", exc_info=True)
            # func_captures_result remains []

        if not func_captures_result:
            logger.debug(f"No function definition captures returned for '{relp}'.")

        # --- Process captures (handle both List and Dict) ---
        definitions: Dict[int, Any] = {}
        names: Dict[int, Any] = {}
        processed_capture_count = 0
        skipped_captures = 0

        try:
            # Handle Dict or List return types.
            if isinstance(func_captures_result, dict):
                logger.debug("Processing captures as Dictionary.")
                # If it's a dict like {'definition': [Node...], 'name': [Node...]}
                definition_nodes = func_captures_result.get('definition', [])
                name_nodes = func_captures_result.get('name', [])

                for node in definition_nodes:
                    if node:
                        definitions[node.id] = node
                    else:
                        skipped_captures += 1
                for node in name_nodes:
                    if node and node.parent:
                        names[node.parent.id] = node
                    else:
                        skipped_captures += 1
                processed_capture_count = len(definition_nodes) + len(name_nodes)

            elif isinstance(func_captures_result, list):
                logger.debug("Processing captures as List.")
                # If it's a list like [(Node, 'definition'), (Node, 'name'), ...]
                for item in func_captures_result:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        node, cap_name = item
                        if node is None:
                            logger.warning(f"Skipping capture with None node in {relp}. Capture name: {cap_name}")
                            skipped_captures += 1
                            continue

                        if cap_name == "definition":
                            definitions[node.id] = node
                        elif cap_name == "name":
                            if node.parent:
                                names[node.parent.id] = node
                            else:
                                logger.warning(
                                    f"Capture '{cap_name}' node lacks parent in {relp} at {node.start_point}")
                                skipped_captures += 1
                        else:
                            logger.warning(
                                f"Unexpected capture name '{cap_name}' found in {relp} at {node.start_point}")
                            skipped_captures += 1
                        processed_capture_count += 1
                    else:
                        logger.error(
                            f"Error processing capture list item in {relp}: Expected a pair (Node, str), but got: {item!r}. Skipping item.")
                        skipped_captures += 1
            else:
                logger.error(f"Unexpected capture result type in {relp}: {type(func_captures_result)}. Cannot process.")

            logger.debug(
                f"Processed {processed_capture_count} captures, skipped {skipped_captures} malformed/unexpected captures.")

        except Exception as e:
            logger.error(f"Error processing raw captures in {relp}: {e}", exc_info=True)
            continue  # Skip processing definitions for this file on error

        logger.debug(f"Processed captures into {len(definitions)} definitions and {len(names)} names for '{relp}'.")

        found_in_file = 0
        for def_id, func_node in definitions.items():
            name_node = names.get(def_id)
            # Use safe get_node_text which handles None
            name = get_node_text(name_node, text).strip()

            if not name:
                t = func_node.type  # Use type directly
                if lang_name == "swift" and ("initializer" in t or "deinitializer" in t):
                    name = "<init>"
                else:
                    # Log more context about the unnamed function
                    unnamed_code_snippet = get_node_text(func_node, text)[:100]
                    logger.warning(
                        f"Could not extract name for function node type '{t}' at {func_node.start_point} in {relp}. Snippet: '{unnamed_code_snippet}...'. Skipping.")
                    continue

            s_byte, e_byte = func_node.start_byte, func_node.end_byte
            s_line = func_node.start_point[0] + 1
            code = text[s_byte:e_byte]  # Extract code only once needed
            logger.debug(f"Processing function definition: '{name}' at line {s_line} in '{relp}'")

            class_name = ""
            try:
                if lang_name == "go" and func_node.type == "method_declaration":
                    class_name = _extract_go_receiver_type(func_node) or _enclosing_class_name_generic(func_node)
                else:
                    class_name = _enclosing_class_name_generic(func_node)
                if class_name:
                    logger.debug(f"  Associated class/receiver name: '{class_name}'")
            except Exception as e:
                logger.warning(f"Error extracting class name for '{name}' in {relp}: {e}", exc_info=True)

            fe = FuncEntry(
                func_id=mk_func_id(relp, name, s_line),
                file_rel=relp,
                file_abs=absp,
                name=name,
                line=s_line,
                start_byte=s_byte,
                end_byte=e_byte,
                code=code,  # Assign extracted code
                params=[],  # TODO: Extract params if needed later
                calls=[],  # Calls will be extracted in a separate step if needed
                lang=lang_name,
                class_name=class_name or ""
            )

            index[fe.func_id] = fe
            found_in_file += 1
            total_funcs_indexed += 1

        logger.debug(f"Finished processing '{relp}', added {found_in_file} function entries.")
        processed_files += 1
        # --- End file loop ---

    logger.info(f"Finished building function index. Processed {processed_files} files.")
    logger.info(f"Skipped {skipped_ext} files (extension), {skipped_read} (read error/empty), "
                f"{skipped_unsupported_lang} (unsupported lang), {skipped_parse_fail} (parse error).")
    logger.info(f"Total functions indexed: {total_funcs_indexed}")  # Use accumulated count
    return index


# ====================== Core Logic ======================
def iter_code_files(root: Path) -> List[Path]:
    logger = logging.getLogger(__name__)  # Use module logger
    out: List[Path] = []
    skip = {"node_modules", ".git", "dist", "build", "out", ".next", ".turbo", "__pycache__", ".venv", "venv", "vendor",
            "target", ".gradle", ".mvn", "bin", "obj"}
    logger.info(f"Searching for code files under '{root}', skipping directories: {skip}")

    file_count = 0
    dir_count = 0
    skipped_dir_count = 0

    for r_str, ds, fs in os.walk(root, topdown=True):  # Ensure topdown=True for skipping
        r = Path(r_str)  # Convert root string to Path object
        dir_count += 1
        logger.debug(f"Scanning directory: {r}")

        original_ds_len = len(ds)
        ds[:] = [d for d in ds if d not in skip and not d.startswith(".")]
        skipped_in_dir = original_ds_len - len(ds)
        if skipped_in_dir > 0:
            logger.debug(f"Pruned {skipped_in_dir} subdirectories in '{r}'")
            skipped_dir_count += skipped_in_dir

        for f in fs:
            file_count += 1
            try:
                p = r / f  # Use Path object directly
                if p.suffix.lower() in ALL_EXTS:
                    out.append(p)
                    # logger.debug(f"Found code file: {p}") # Too verbose
                # else: logger.debug(f"Skipping non-code file: {p}")
            except Exception as e:
                logger.error(f"Error processing file path '{r}/{f}': {e}", exc_info=True)

    logger.info(
        f"File search complete. Found {len(out)} code files out of {file_count} total files checked across {dir_count} directories (pruned {skipped_dir_count} subdirs).")
    return out


def load_entry_hints_from_refined_json(root: Path, refined_json_path: Path, logger: logging.Logger) -> Dict[
    str, Dict[str, Any]]:
    logger.info(f"Loading entry hints from: {refined_json_path}")
    try:
        text = refined_json_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.error(f"Failed to read refined JSON file {refined_json_path}: {e}", exc_info=True)
        text = "{}"
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {refined_json_path}: {e}", exc_info=True)
        data = {}
    if not isinstance(data, dict):
        logger.error(f"Parsed JSON from {refined_json_path} is not a dictionary.")
        return {}

    hints: Dict[str, Dict[str, Any]] = {}
    valid_hints = 0
    invalid_hints = 0
    for tool_name, tool_data in data.items():
        if not isinstance(tool_data, dict) or tool_data.get("status") != "resolved":
            logger.debug(f"Skipping tool '{tool_name}': status not 'resolved' or invalid data.")
            continue
        handler = tool_data.get("handler")
        if not isinstance(handler, dict):
            logger.warning(f"Skipping tool '{tool_name}': 'handler' data is missing or not a dict.")
            invalid_hints += 1
            continue
        file_rel, code_block = handler.get("file"), handler.get("code_block")
        start_line, end_line = handler.get("start_line"), handler.get("end_line")

        # More robust check for essential fields
        missing_fields = []
        if not file_rel: missing_fields.append("'file'")
        if not code_block: missing_fields.append("'code_block'")
        if start_line is None: missing_fields.append("'start_line'")
        if end_line is None: missing_fields.append("'end_line'")

        if missing_fields:
            logger.warning(
                f"Skipping tool '{tool_name}': missing required handler fields: {', '.join(missing_fields)}.")
            invalid_hints += 1
            continue

        # Basic type check (start/end line should ideally be numbers)
        if not isinstance(start_line, int) or not isinstance(end_line, int):
            logger.warning(f"Skipping tool '{tool_name}': 'start_line' or 'end_line' is not an integer.")
            invalid_hints += 1
            continue

        signature = code_block.splitlines()[0].strip() if code_block and code_block.strip() else ""
        hints[tool_name] = {"file_rel": file_rel, "signature": signature, "snippet": code_block,
                            "start_line": start_line, "end_line": end_line}
        valid_hints += 1
        logger.debug(f"Loaded valid hint for tool '{tool_name}'")

    logger.info(f"Loaded {valid_hints} valid hints, skipped {invalid_hints} invalid/unresolved entries.")
    return hints


@dataclass
class FuncCandidate:
    """Helper data class used to score candidate functions."""
    node: Any  # tree-sitter node.
    name: str  # Function name.
    start_line: int  # Start line number.


def build_entry_from_switch_case(tool: str, hint: Dict[str, Any], root: Path,
                                 ts_manager: TreeSitterManager, logger: logging.Logger) -> Optional[FuncEntry]:
    """
    Multi-language minimal branch extractor.
    Supports:
      A: js, ts, tsx, java, csharp, c, cpp, php, swift, kotlin  (C-like switch)
      B: go                                                    (Go switch)
      C: rust                                                  (match arms)
      D: python                                                (match/case, Py3.10+)
    """
    import re

    file_rel = hint.get("file_rel") or hint.get("file") or ""
    if not file_rel:
        logger.error(f"Tool '{tool}': No file given for switch-case builder.")
        return None
    p = (root / file_rel)
    if not p.is_file():
        logger.error(f"Tool '{tool}': File not found: {p}")
        return None

    text = read_text(p)
    if not text:
        return None

    ext = p.suffix.lower()
    lang_name = LANGUAGE_MAPPING.get(ext, {}).get("name", "").lower()

    # -------- helpers --------
    def skip_comments_ws(idx: int) -> int:
        # skip whitespace, //..., /*...*/, #... (for py, go handles //, /* */ too)
        n = len(text)
        while idx < n:
            c = text[idx]
            if c in " \t\r\n":
                idx += 1
                continue
            if text.startswith("//", idx):
                while idx < n and text[idx] != "\n":
                    idx += 1
                continue
            if text.startswith("/*", idx):
                idx += 2
                while idx < n and not text.startswith("*/", idx):
                    idx += 1
                idx = min(n, idx + 2)
                continue
            if c == '#' and lang_name == "python":
                while idx < n and text[idx] != "\n":
                    idx += 1
                continue
            break
        return idx

    def brace_window(open_idx: int) -> Optional[int]:
        # return end_byte (exclusive) for block starting at '{'
        n = len(text)
        depth = 0
        j = open_idx
        in_single = in_double = in_template = False
        in_line = in_block = False
        esc = False
        while j < n:
            ch = text[j]
            # comments
            if not (in_single or in_double or in_template):
                if not in_block and not in_line and text.startswith("//", j):
                    in_line = True; j += 2; continue
                if not in_block and not in_line and text.startswith("/*", j):
                    in_block = True; j += 2; continue
                if in_line:
                    if ch == "\n": in_line = False
                    j += 1; continue
                if in_block:
                    if text.startswith("*/", j): in_block = False; j += 2; continue
                    j += 1; continue
            # strings/template
            if not in_double and not in_template and ch == "'" and not in_single:
                if not esc: in_single = True
                j += 1; esc = False; continue
            if in_single:
                if ch == "\\": esc = not esc
                elif ch == "'" and not esc: in_single = False; esc = False
                else: esc = False
                j += 1; continue
            if not in_single and not in_template and ch == '"' and not in_double:
                if not esc: in_double = True
                j += 1; esc = False; continue
            if in_double:
                if ch == "\\": esc = not esc
                elif ch == '"' and not esc: in_double = False; esc = False
                else: esc = False
                j += 1; continue
            if not in_single and not in_double and ch == '`' and not in_template and lang_name in ("javascript","typescript","tsx"):
                in_template = True; j += 1; esc = False; continue
            if in_template:
                if ch == "\\": esc = not esc; j += 1; continue
                if ch == '`' and not esc: in_template = False; esc = False; j += 1; continue
                esc = False; j += 1; continue
            # braces
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return None

    # -------- per language group detection & extraction --------

    start_byte = end_byte = None

    if lang_name in ("javascript","typescript","tsx","java","csharp","c","cpp","php","swift","kotlin"):
        # A: C-like switch
        # Label form: case "<tool>":, with single quotes, double quotes, or unquoted values.
        m = re.search(rf'(?m)^\s*case\s+([\'"]){re.escape(tool)}\1\s*:', text)
        if not m:
            # Loose unquoted match, for example case getProposal:.
            m = re.search(rf'(?m)^\s*case\s+{re.escape(tool)}\s*:', text)
        if not m:
            logger.error(f"Tool '{tool}': no case label found for {lang_name}.")
            return None
        start_label = m.start()
        after_colon = m.end()

        i = skip_comments_ws(after_colon)
        if i < len(text) and text[i] == '{':
            # Block-scoped case style: case "X": { ... }.
            block_end = brace_window(i)
            if block_end is None:
                logger.error(f"Tool '{tool}': unbalanced braces in case block.")
                return None
            start_byte, end_byte = start_label, block_end
        else:
            # Non-block-scoped style: from this case to the next case/default.
            start_byte = start_label
            # Find the end of the switch body that contains this case.
            # Approximation: scan for the next case/default line or the closing brace.
            mnext = re.search(r'(?m)^\s*(case\b|default\s*:)', text[after_colon:])
            if mnext:
                end_byte = after_colon + mnext.start()
            else:
                # Treat the nearest closing brace line as the switch end.
                probe = text[after_colon:]
                close_pos = probe.rfind('}')
                end_byte = after_colon + (close_pos + 1 if close_pos >= 0 else len(probe))

    elif lang_name == "go":
        # B: Go switch
        # Match case "<tool>": or case <tool>:.
        m = re.search(rf'(?m)^\s*case\s+(?:([\'"]){re.escape(tool)}\1|{re.escape(tool)})\s*:', text)
        if not m:
            logger.error(f"Tool '{tool}': no Go case label found.")
            return None
        start_label = m.start()
        after_colon = m.end()
        # From this case to the next case/default or switch end; Go cases usually have no separate braces.
        mnext = re.search(r'(?m)^\s*(case\b|default\b)\s*:', text[after_colon:])
        if mnext:
            end_byte = after_colon + mnext.start()
        else:
            # Approximate the nearest closing brace as the switch end.
            probe = text[after_colon:]
            close_pos = probe.rfind('}')
            end_byte = after_colon + (close_pos + 1 if close_pos >= 0 else len(probe))
        start_byte = start_label

    elif lang_name == "rust":
        # C: Rust match arms:   "<tool>" => { ... } or "<tool>" => expr,
        m = re.search(rf'(?m)^\s*["\']{re.escape(tool)}["\']\s*=>', text)
        if not m:
            logger.error(f"Tool '{tool}': no Rust match arm found.")
            return None
        arm_start = m.start()
        j = m.end()
        j = skip_comments_ws(j)
        if j < len(text) and text[j] == '{':
            block_end = brace_window(j)
            if block_end is None:
                logger.error(f"Tool '{tool}': unbalanced braces in Rust arm.")
                return None
            start_byte, end_byte = arm_start, block_end
        else:
            # Expression arm: read until the first comma or closing brace outside strings/comments.
            n = len(text); in_s = in_d = in_block = in_line = False; esc = False
            while j < n:
                ch = text[j]
                if not (in_s or in_d):
                    if not in_block and not in_line and text.startswith("//", j):
                        in_line = True; j += 2; continue
                    if not in_block and not in_line and text.startswith("/*", j):
                        in_block = True; j += 2; continue
                    if in_line:
                        if ch == "\n": in_line = False
                        j += 1; continue
                    if in_block:
                        if text.startswith("*/", j): in_block = False; j += 2; continue
                        j += 1; continue
                if not in_d and ch == "'" and not in_s:
                    if not esc: in_s = True
                    j += 1; esc = False; continue
                if in_s:
                    if ch == "\\": esc = not esc
                    elif ch == "'" and not esc: in_s = False; esc = False
                    else: esc = False
                    j += 1; continue
                if not in_s and ch == '"' and not in_d:
                    if not esc: in_d = True
                    j += 1; esc = False; continue
                if in_d:
                    if ch == "\\": esc = not esc
                    elif ch == '"' and not esc: in_d = False; esc = False
                    else: esc = False
                    j += 1; continue
                if ch == ',' or ch == '}':
                    start_byte, end_byte = arm_start, j + (1 if ch == '}' else 0)
                    break
                j += 1
            if start_byte is None:
                start_byte, end_byte = arm_start, j
    elif lang_name == "python":
        # D: Python match/case
        # Allow case "<tool>": or case '<tool>':.
        m = re.search(rf'(?m)^\s*case\s+([\'"]){re.escape(tool)}\1\s*:', text)
        if not m:
            logger.error(f"Tool '{tool}': no Python case arm found.")
            return None
        line_start = text.rfind('\n', 0, m.start()) + 1
        start_byte = line_start
        # From this branch to the next when/else/end.
        line = text[line_start: text.find('\n', line_start)]
        indent = len(line) - len(line.lstrip(' '))
        # If possible, stop at end.
        pos = text.find('\n', m.end())
        if pos == -1: pos = len(text)
        end_cursor = pos + 1
        n = len(text)
        while end_cursor < n:
            nl = text.find('\n', end_cursor)
            if nl == -1: nl = n
            seg = text[end_cursor:nl]
            # Try to include the entire when branch.
            if re.match(r'^\s*(case\b|match\b)', seg):
                break
            # Fallback to the current line only.
            if seg.strip():
                cur_indent = len(seg) - len(seg.lstrip(' '))
                if cur_indent <= indent:
                    break
            end_cursor = nl + 1
        end_byte = end_cursor
    else:
        logger.warning(f"Tool '{tool}': language '{lang_name}' not in switch extractor; fallback to strict window.")
        return build_entry_from_hint_old(tool, hint, root, ts_manager, logger)

    if start_byte is None or end_byte is None or end_byte <= start_byte:
        logger.error(f"Tool '{tool}': failed to compute case window.")
        return None

    code = text[start_byte:end_byte]

    fe = FuncEntry(
        func_id=mk_func_id(file_rel, f"<block_{tool}>", hint.get("start_line", 1)),
        file_rel=file_rel,
        file_abs=abs_str(p),
        name=f"<block_{tool}>",
        line=hint.get("start_line", 1),
        start_byte=start_byte,
        end_byte=end_byte,
        code=code,
        lang=lang_name,
    )

    # calls in-window
    try:
        tree = ts_manager.parse(lang_name, text)
        root_node = tree.root_node
        call_caps = ts_manager.query(lang_name, root_node, "calls")
    except Exception:
        call_caps = []

    items = []
    if isinstance(call_caps, dict):
        items = [(n, 'call') for n in call_caps.get('call', [])]
    elif isinstance(call_caps, list):
        items = call_caps

    uniq = {}
    for n, cap in items:
        if cap != 'call' or n is None:
            continue
        if not (start_byte <= n.start_byte <= n.end_byte <= end_byte):
            continue
        inner = ts_manager.query(lang_name, n, "calls")
        callee = n
        inner_items = []
        if isinstance(inner, dict):
            inner_items = [(x, 'callee') for x in inner.get('callee', [])]
        elif isinstance(inner, list):
            inner_items = inner
        for x, nm in inner_items:
            if nm == 'callee' and x:
                callee = x
                break

        cs = CallSite(
            callee_text=get_node_text(callee, text),
            line=n.start_point[0] + 1,
            start_byte=n.start_byte,
            end_byte=n.end_byte,
            call_src=get_node_text(n, text),
        )
        uniq[(cs.start_byte, cs.end_byte, cs.callee_text)] = cs

    fe.calls = list(uniq.values())
    logger.info(f"Tool '{tool}': case/match block built ({lang_name}) with {len(fe.calls)} calls.")
    return fe

def build_entry_from_hint_function(tool: str, hint: Dict[str, Any], root: Path, ts_manager: TreeSitterManager,
                              logger: logging.Logger) -> Optional[FuncEntry]:
    """
    Named-function path only: Uses candidate scoring among named defs (no anon fallback).
    """
    logger.warning(f"Tool '{tool}': Using DEPRECATED 'build_entry_from_hint_old' (Candidate Scoring).")
    # ... (rest of the old function implementation) ...
    # Ensure this function also uses the passed logger instance if kept
    file_rel = hint.get("file_rel") or ""
    if not file_rel: logger.error(f"Tool '{tool}': Hint is missing 'file_rel'."); return None

    p = root / file_rel
    if not p.is_file(): logger.error(f"Tool '{tool}': File not found or not a file at '{p}'."); return None

    text = read_text(p)
    if not text: logger.warning(f"Tool '{tool}': File is empty at '{p}'."); return None

    ext = p.suffix.lower()
    if ext not in LANGUAGE_MAPPING:
        logger.error(f"Tool '{tool}': File extension '{ext}' is not supported.");
        return None

    lang_name = LANGUAGE_MAPPING[ext]["name"]
    if not lang_name or not ts_manager.is_supported(lang_name):
        logger.error(f"Tool '{tool}': Language '{lang_name}' parser is not available.");
        return None

    try:
        tree = ts_manager.parse(lang_name, text)
    except Exception as e:
        logger.error(f"Tool '{tool}': Failed to parse AST for '{file_rel}': {e}", exc_info=True)
        return None

    hint_snippet = hint.get("snippet", "")
    hint_start_line = hint.get("start_line", 1)
    hint_func_name = extract_hint_name(hint_snippet, lang_name)  # Uses logging

    if hint_func_name:
        logger.info(f"Tool '{tool}': Extracted hint name '{hint_func_name}' from snippet.")
    else:
        logger.warning(f"Tool '{tool}': Could not extract name from snippet. Will rely on location only.")

    all_functions: List[FuncCandidate] = []
    try:
        func_captures_result = ts_manager.query(lang_name, tree.root_node,
                                                "functions")  # Uses logging, returns List or Dict

        definitions: Dict[int, Any] = {}
        names: Dict[int, Any] = {}
        # Robust iteration for captures (handle List or Dict)
        if isinstance(func_captures_result, dict):
            for node in func_captures_result.get('definition', []):
                if node: definitions[node.id] = node
            for node in func_captures_result.get('name', []):
                if node and node.parent: names[node.parent.id] = node
        elif isinstance(func_captures_result, list):
            for item in func_captures_result:
                if not (isinstance(item, (tuple, list)) and len(item) == 2): continue
                node, cap_name = item
                if node is None: continue
                if cap_name == "definition":
                    definitions[node.id] = node
                elif cap_name == "name" and node.parent:
                    names[node.parent.id] = node

        for def_id, func_node in definitions.items():
            name_node = names.get(def_id)
            name = get_node_text(name_node, text).strip()  # Safe get_node_text

            if not name:
                t = func_node.type
                if lang_name == "swift" and ("initializer" in t or "deinitializer" in t):
                    name = "<init>"
                else:
                    continue

            all_functions.append(FuncCandidate(
                node=func_node,
                name=name,
                start_line=func_node.start_point[0] + 1
            ))
        logger.debug(f"Tool '{tool}': Found {len(all_functions)} function candidates in '{file_rel}'.")

    except Exception as e:
        logger.error(f"Tool '{tool}': Failed to query/process functions from AST: {e!r}", exc_info=True);
        return None

    if not all_functions:
        logger.error(f"Tool '{tool}': No function candidates found in file '{file_rel}'.");
        return None

    F_before: Optional[FuncCandidate] = None
    F_after: Optional[FuncCandidate] = None
    for func in sorted(all_functions, key=lambda f: f.start_line):  # Ensure sorted
        if func.start_line <= hint_start_line:
            F_before = func
        elif func.start_line > hint_start_line:
            F_after = func
            break

    candidates = [f for f in [F_before, F_after] if f]
    logger.debug(f"Tool '{tool}': Candidates near line {hint_start_line}: {[c.name for c in candidates]}")

    if not candidates:
        logger.error(f"Tool '{tool}': Could not find any candidates near line {hint_start_line}.");
        return None

    best_candidate: Optional[FuncCandidate] = None
    best_score = -1

    for cand in candidates:
        score = 0
        if hint_func_name and cand.name == hint_func_name: score += 100
        dist = abs(cand.start_line - hint_start_line)
        score += max(0, 50 - dist * 2)  # Proximity score decreasing with distance
        # if cand == F_after: score += 50
        # elif cand == F_before: score += 20
        logger.debug(f"  Candidate '{cand.name}' (line {cand.start_line}), Score: {score}")

        if score > best_score:
            best_score = score
            best_candidate = cand

    if not best_candidate:
        logger.error(f"Tool '{tool}': Internal error: Scoring failed to select a candidate.");
        return None

    func_node = best_candidate.node
    found_name = best_candidate.name

    if hint_func_name and found_name != hint_func_name:
        logger.warning(
            f"Tool '{tool}': Hint name '{hint_func_name}' MISMATCHED best location match '{found_name}' (line {best_candidate.start_line}, score {best_score}). Trusting location match.")
    elif hint_func_name:
        logger.info(
            f"Tool '{tool}': Located function via Candidate Scoring (Name & Location match: '{found_name}', line {best_candidate.start_line}, score {best_score}).")
    else:
        logger.info(
            f"Tool '{tool}': Located function via Candidate Scoring (Location only: '{found_name}', line {best_candidate.start_line}, score {best_score}).")

    final_start_byte = func_node.start_byte
    final_end_byte = func_node.end_byte
    final_start_line = func_node.start_point[0] + 1
    code = get_node_text(func_node, text)
    name = f"<block_{tool}>"  # Keep original naming convention

    fe = FuncEntry(
        func_id=mk_func_id(file_rel, name, final_start_line),
        file_rel=file_rel,
        file_abs=abs_str(p),
        name=name,
        line=final_start_line,
        start_byte=final_start_byte,
        end_byte=final_end_byte,
        code=code,
        lang=lang_name
    )

    call_captures_result = ts_manager.query(lang_name, func_node, "calls")  # Uses logging, returns List or Dict
    logger.debug(
        f"Tool '{tool}': Found {len(call_captures_result) if isinstance(call_captures_result, (list, dict)) else 'N/A'} raw call captures within selected function '{found_name}' (type: {type(call_captures_result)}).")

    uniq = {}
    calls_processed = 0
    # Robust iteration for captures (handle List or Dict)
    call_items_to_process = []
    if isinstance(call_captures_result, dict):
        call_items_to_process = [(n, 'call') for n in call_captures_result.get('call', [])]
    elif isinstance(call_captures_result, list):
        call_items_to_process = call_captures_result
    # else: log error?

    for item in call_items_to_process:
        if not (isinstance(item, (tuple, list)) and len(item) == 2):
            logger.warning(f"Tool '{tool}': Skipping malformed call capture item in old hint builder: {item!r}")
            continue
        call_node, cap_name = item
        if cap_name != "call" or call_node is None: continue

        inner_caps = ts_manager.query(lang_name, call_node, "calls")  # Returns List or Dict
        callee_node = call_node  # Default

        inner_items = []
        if isinstance(inner_caps, dict):
            inner_items = [(n, 'callee') for n in inner_caps.get('callee', [])]
        elif isinstance(inner_caps, list):
            inner_items = inner_caps
        # else: log error?

        for inner_node, inner_name in inner_items:
            if inner_name == "callee" and inner_node:
                callee_node = inner_node
                break

        try:
            callee_text = get_node_text(callee_node, text)
            call_src_text = get_node_text(call_node, text)
        except Exception as text_e:
            logger.warning(
                f"Tool '{tool}': Error getting text for call node at {call_node.start_point} in {file_rel} (within candidate scoring): {text_e}")
            continue

        cs = CallSite(
            callee_text=callee_text,
            line=call_node.start_point[0] + 1,
            start_byte=call_node.start_byte,
            end_byte=call_node.end_byte,
            call_src=call_src_text,
        )
        uniq[(cs.start_byte, cs.end_byte, cs.callee_text)] = cs
        calls_processed += 1

    fe.calls = list(uniq.values())
    unique_calls_count = len(fe.calls)
    logger.info(
        f"Tool '{tool}': Built entry block (Candidate Scoring for '{found_name}') with {unique_calls_count} unique calls (processed {calls_processed} raw).")
    return fe

def build_entry_from_hint_old(tool: str, hint: Dict[str, Any], root: Path,
                          ts_manager: TreeSitterManager,
                          logger: logging.Logger) -> Optional[FuncEntry]:
    """Build an entry function candidate from a resolved hint using the older resolver."""
    file_rel = hint.get("file_rel") or hint.get("file") or ""
    if not file_rel:
        logger.error(f"Tool '{tool}': No file in hint.")
        return None

    # Use an explicit entry hint when one is available.
    ext = Path(file_rel).suffix.lower()
    lang_name = LANGUAGE_MAPPING.get(ext, {}).get("name", "")

    snippet = hint.get("snippet") or hint.get("code_block") or ""
    kind = classify_hint_snippet(snippet, lang_name)
    logger.info(f"Tool '{tool}': hint classified as {kind}.")

    if kind == "switch_case":
        # Build candidates from parsed function definitions.
        fe = build_entry_from_switch_case(tool, hint, root, ts_manager, logger)
        if fe and fe.code.strip():
            return fe
        logger.warning(f"Tool '{tool}': switch-case AST builder failed or empty. Falling back to STRICT window.")
        return build_entry_from_hint_old(tool, hint, root, ts_manager, logger)

    if kind == "function":
        fe = build_entry_from_hint_function(tool, hint, root, ts_manager, logger)
        if fe and fe.code.strip():
            return fe
        logger.warning(f"Tool '{tool}': functional builder failed or empty. Falling back to STRICT window.")
        return build_entry_from_hint_old(tool, hint, root, ts_manager, logger)

    # Score candidates by hint and name similarity.
    return build_entry_from_hint_old(tool, hint, root, ts_manager, logger)

def build_name_lookup(index: Dict[str, FuncEntry]) -> Dict[str, List[str]]:
    logger = logging.getLogger(__name__)  # Use module logger
    logger.info("Building function name lookup table...")
    lut: Dict[str, List[str]] = {};
    count = 0
    for fid, fe in index.items():
        # Extract base name robustly (handle potential errors)
        try:
            base_name = fe.name.split('.')[-1].split('::')[-1]
            lut.setdefault(base_name, []).append(fid)
            count += 1
        except Exception as e:
            logger.warning(f"Error processing name '{fe.name}' for func_id '{fid}': {e}")
    logger.info(f"Built lookup table with {len(lut)} unique base names mapping to {count} total function entries.")
    return lut


def resolve_callee_to_func_id(callee_text: str,
                              index: Dict[str, FuncEntry],
                              name_lut: Dict[str, List[str]],
                              caller_fe: FuncEntry,
                              logger: logging.Logger) -> Optional[str]:  # Pass logger
    """
    Resolves a callee text to the most likely FuncEntry ID based on context.
    """
    logger.debug(f"Resolving callee '{callee_text}' called from '{caller_fe.func_id}'")
    if not callee_text:
        return None

    # --- Parse Callee Text ---
    parts = [p for p in re.split(r"[.:]", callee_text) if p]  # Split by . or :
    if not parts: return None  # Handle empty string after split

    if len(parts) >= 2:
        # Simplistic: assume last part is method, second to last is receiver/class
        # This needs refinement for complex cases like A.B.C() or A::B::C()
        recv, b_name = parts[-2], parts[-1]
        logger.debug(f"  Parsed as receiver='{recv}', base_name='{b_name}'")
    else:
        recv, b_name = None, parts[0]
        logger.debug(f"  Parsed as base_name='{b_name}' (no receiver)")

    # --- Determine Preferred Class/Receiver ---
    prefer_class = ""
    if recv:
        # Handle 'this', 'self', 'super' etc. based on language conventions if needed
        if recv.lower() in ("this", "self", "super") and caller_fe.class_name:
            prefer_class = caller_fe.class_name
            logger.debug(f"  Using caller's class '{prefer_class}' based on receiver '{recv}'.")
        # Check if receiver looks like a class/module name (e.g., starts with Uppercase or contains '_')
        elif re.match(r"^[A-Z_]", recv) or '_' in recv:  # Simple heuristic
            prefer_class = recv
            logger.debug(f"  Using receiver '{prefer_class}' as preferred class.")
        # Else: receiver might be an instance variable, less useful for direct matching

    # --- Find Candidates ---
    cands = name_lut.get(b_name, [])
    if not cands:
        logger.debug(f"  No functions found in lookup table with base name '{b_name}'.")
        return None
    logger.debug(f"  Found {len(cands)} candidates with base name '{b_name}'.")

    # --- Score Candidates ---
    top_fid, top_score = None, -10 ** 9
    scores = []  # For logging

    for fid in cands:
        fe = index.get(fid)
        if not fe: continue

        score = 0
        score_details = []

        # 1. Exact File Match (Highest Priority)
        if fe.file_rel == caller_fe.file_rel:
            score += 100
            score_details.append("same_file(+100)")

        # 2. Preferred Class/Receiver Match (High Priority)
        if prefer_class and fe.class_name and fe.class_name == prefer_class:
            score += 50
            score_details.append(f"pref_class_match({prefer_class}, +50)")
        elif prefer_class and fe.class_name and fe.class_name.endswith(
                prefer_class):  # Allow partial match (e.g., module::Class vs Class)
            score += 30
            score_details.append(f"pref_class_suffix_match({prefer_class}, +30)")

        # 3. Language Match (Medium Priority)
        if fe.lang and caller_fe.lang and fe.lang == caller_fe.lang:
            score += 20
            score_details.append("same_lang(+20)")

        # 4. Name Specificity (Lower Priority - avoid overly penalizing short names)
        # Maybe reward longer/more specific matches slightly?
        # if len(fe.name) > len(b_name): score += 5

        # 5. Fallback: Base Name Match (already implicitly true)
        # score += 1 # Small base score

        scores.append((fid, score, ", ".join(score_details)))

        if score > top_score:
            top_score = score
            top_fid = fid
        # Tie-breaking (optional): prefer shorter file paths? Or closer line numbers?
        # For now, first highest score wins.

    # Log scoring results
    logger.debug("  Candidate Scores:")
    for fid, score, details in sorted(scores, key=lambda x: x[1], reverse=True)[:5]:  # Log top 5
        logger.debug(f"    - {fid}: Score={score} ({details}) {'[WINNER]' if fid == top_fid else ''}")

    if top_fid:
        logger.debug(f"  Resolved '{callee_text}' to '{top_fid}' with score {top_score}")
    else:
        logger.debug(f"  Could not resolve '{callee_text}' to a specific function.")

    return top_fid


def build_nested_calls(fe: FuncEntry, index: Dict[str, FuncEntry], name_lut: Dict[str, List[str]], root: Path,
                       max_depth: int, seen: Set[str], logger: logging.Logger) -> Dict[str, Any]:  # Pass logger
    """Recursively builds the call chain structure."""
    logger.debug(f"Building nested calls for '{fe.func_id}', depth remaining: {max_depth}")
    # Basic info for the current function node
    obj = {
        "func": f"{fe.file_abs}::{fe.name}",  # Use absolute path for clarity? Or keep relative? Using abs for now.
        "func_id": fe.func_id,  # Add func_id for easier cross-referencing
        "code": fe.code,
        "params": fe.params,
        "calls": []
    }

    if max_depth <= 0:
        logger.debug(f"  Max depth reached for '{fe.func_id}'. Stopping recursion.")
        return obj
    if not fe.calls:
        logger.debug(f"  No calls found within '{fe.func_id}'.")
        return obj

    logger.debug(f"  Processing {len(fe.calls)} calls within '{fe.func_id}'...")
    for i, call in enumerate(fe.calls):
        logger.debug(f"    Call {i + 1}/{len(fe.calls)}: Text='{call.callee_text}' at line {call.line}")
        callee_fid = resolve_callee_to_func_id(call.callee_text, index, name_lut, fe, logger)  # Pass logger

        nested_calls_list = []  # Store nested calls here
        callee_code = ""
        resolved_func_id = None  # Track the resolved ID

        if callee_fid:
            resolved_func_id = callee_fid
            logger.debug(f"      Resolved to func_id: '{callee_fid}'")
            if callee_fid == fe.func_id:
                logger.debug("      Skipping direct recursion.")
            elif callee_fid in seen:
                logger.debug(f"      Already visited '{callee_fid}' in this path. Skipping recursion.")
            else:
                callee_fe = index.get(callee_fid)
                if callee_fe:
                    callee_code = callee_fe.code or ""
                    seen.add(callee_fid)  # Add before recursive call
                    logger.debug(f"      Recursing into '{callee_fid}'...")
                    nested_result = build_nested_calls(callee_fe, index, name_lut, root, max_depth - 1, seen,
                                                       logger)  # Pass logger
                    seen.remove(callee_fid)  # Remove after returning
                    nested_calls_list = nested_result.get("calls", [])
                    logger.debug(f"      Returned from '{callee_fid}'. Found {len(nested_calls_list)} nested calls.")
                else:
                    logger.warning(f"      Resolved to func_id '{callee_fid}', but FuncEntry not found in index!")
        else:
            logger.debug("      Could not resolve callee.")

        # Structure for each call site
        call_obj = {
            "func": call.callee_text,  # The text as it appears in the code
            "resolved_func_id": resolved_func_id,  # The resolved ID, if any
            "file": fe.file_abs,  # File where the call occurs
            "line": call.line,  # Line where the call occurs
            "loc": {"start_byte": call.start_byte, "end_byte": call.end_byte},
            "sink": bool(call.sink),  # Assuming sink detection happens elsewhere
            "args": call.arg_text,  # TODO: Extract arguments if needed
            "src": call.call_src,  # Full source text of the call expression
            "code": callee_code or "",  # Code of the resolved callee, if found
            "calls": nested_calls_list  # The list of calls made by the callee
        }
        obj["calls"].append(call_obj)

    logger.debug(f"Finished building nested calls for '{fe.func_id}'. Total calls added: {len(obj['calls'])}")
    return obj


def _collect_calls_in_window(lang_name: str, text: str, ts_manager: TreeSitterManager,
                             start_byte: int, end_byte: int, logger: logging.Logger) -> List[CallSite]:
    """Collect calls within a given byte window (multi-language)."""
    try:
        tree = ts_manager.parse(lang_name, text)
        root_node = tree.root_node
        call_caps = ts_manager.query(lang_name, root_node, "calls")
    except Exception as e:
        logger.error(f"Collect calls failed (parse/query): {e}", exc_info=True)
        return []

    items = []
    if isinstance(call_caps, dict):
        items = [(n, 'call') for n in call_caps.get('call', [])]
    elif isinstance(call_caps, list):
        items = call_caps

    uniq = {}
    for n, cap in items:
        if cap != 'call' or n is None:
            continue
        if not (start_byte <= n.start_byte <= n.end_byte <= end_byte):
            continue
        inner = ts_manager.query(lang_name, n, "calls")
        callee = n
        inner_items = []
        if isinstance(inner, dict):
            inner_items = [(x, 'callee') for x in inner.get('callee', [])]
        elif isinstance(inner, list):
            inner_items = inner
        for x, nm in inner_items:
            if nm == 'callee' and x:
                callee = x
                break

        cs = CallSite(
            callee_text=get_node_text(callee, text),
            line=n.start_point[0] + 1,
            start_byte=n.start_byte,
            end_byte=n.end_byte,
            call_src=get_node_text(n, text),
        )
        uniq[(cs.start_byte, cs.end_byte, cs.callee_text)] = cs

    return list(uniq.values())

# ====== PATCH: anon/function split + improved anon body detection ======


def classify_hint_snippet(snippet: str, lang_name: str) -> str:
    """
    Returns: 'switch_case' | 'function' | 'anon_block' | 'unknown'
    (Appended override: the latest definition wins.)
    """
    import re
    if not snippet:
        return "unknown"

    head = "\n".join(snippet.splitlines()[:6]).strip()
    lang = (lang_name or "").lower()

    # switch/case label
    if re.search(r'^\s*case\s+([\'\"]).+?\1\s*:\s*{?', head):
        return "switch_case"

    # named function (multi-language)
    named = [
        r'^\s*(?:async\s+)?function\s+[A-Za-z_]\w*\s*\(',
        r'^\s*def\s+[A-Za-z_]\w*\s*\(',
        r'^\s*(?:public|private|protected|static|\s)*[A-Za-z0-9_<>\[\]]+\s+[A-Za-z_]\w*\s*\(',
        r'^\s*fn\s+[A-Za-z_]\w*\s*\(',
        r'^\s*fun\s+[A-Za-z_]\w*\s*\(',
        r'^\s*func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(',
        r'^\s*function\s+[A-Za-z_]\w*',
        r'^\s*func\s+[A-Za-z_]\w*',
        # Start multiprocessing analysis.
        r'^\s*(?:#?\s*)(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+|\*\s*)?[A-Za-z_$][\w$]*\s*\(',
    ]
    if any(re.search(p, head) for p in named):
        return "function"

    # anonymous / lambda-like blocks with braces (per-language heads)
    arrow_map = [
        (("javascript","typescript","tsx"), [
            r'^\s*(?:async\s+)?\([^)]*\)\s*=>\s*{',
            r'^\s*[A-Za-z_$][\w$]*\s*:\s*(?:async\s+)?\([^)]*\)\s*=>\s*{',
            r'^\s*\[[^\]]+\]\s*:\s*(?:async\s+)?\([^)]*\)\s*=>\s*{',
        ]),
        (("go",), [r'^\s*func\s*\([^)]*\)\s*{']),
        (("php",), [r'^\s*function\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?{']),
        (("java","csharp"), [r'^\s*\([^)]*\)\s*->\s*{']),
        (("c","cpp"), [r'^\s*\[[^\]]*\]\s*\([^)]*\)\s*{', r'^\s*\[[^\]]*\]\s*{']),
        (("rust",), [r'^\s*(?:move\s+)?\|[^|]*\|\s*{']),
        (("kotlin",), [r'^\s*fun\s*\([^)]*\)\s*{', r'^\s*\{\s*[^}]*->']),
        (("swift",), [r'^\s*\{\s*\([^)]*\)\s*in\b', r'^\s*func\s*\([^)]*\)\s*{']),
    ]
    for langs, pats in arrow_map:
        if lang in langs and any(re.search(p, head) for p in pats):
            return "anon_block"

    # fallback: if we can extract a name, treat as function
    try:
        name = extract_hint_name(snippet, lang_name)
        if name:
            return "function"
    except Exception:
        pass

    return "unknown"



def build_entry_from_anon_block(tool: str, hint: Dict[str, Any], root: Path,
                                ts_manager: TreeSitterManager, logger: logging.Logger) -> Optional[FuncEntry]:
    file_rel = hint.get("file_rel") or hint.get("file") or ""
    if not file_rel:
        logger.error(f"Tool '{tool}': Hint missing 'file_rel'."); return None
    p = root / file_rel
    if not p.is_file():
        logger.error(f"Tool '{tool}': File not found: {p}"); return None

    text = read_text(p)
    if not text:
        logger.warning(f"Tool '{tool}': Empty file: {p}"); return None

    ext = p.suffix.lower()
    if ext not in LANGUAGE_MAPPING:
        logger.error(f"Tool '{tool}': Unsupported extension '{ext}'."); return None
    lang_name = LANGUAGE_MAPPING[ext]["name"].lower()

    snippet = hint.get("snippet") or hint.get("code_block") or ""
    if not snippet.strip():
        logger.error(f"Tool '{tool}': anon_block requires 'snippet'."); return None

    start_line = hint.get("start_line")
    end_line = hint.get("end_line")

    import re
    n = len(text)
    # Implementation note.
    region_start, region_end = 0, n
    if isinstance(start_line, int) and start_line >= 1:
        cur, idx = 1, 0
        while idx < n and cur < start_line:
            if text[idx] == '\n': cur += 1
            idx += 1
        region_start = max(0, idx - 300)
        if isinstance(end_line, int) and end_line >= start_line:
            cur, jdx = 1, 0
            while jdx < n and cur < (end_line + 1):
                if text[jdx] == '\n': cur += 1
                jdx += 1
            region_end = min(n, jdx + 300)

    region_text = text[region_start:region_end]

    def _fuzzy_regex(s: str) -> str:
        out, ws = [], False
        for ch in s:
            if ch.isspace():
                if not ws: out.append(r'\s+'); ws = True
            else:
                ws = False; out.append(re.escape(ch))
        return ''.join(out)

    # fuzzy match the snippet
    pat = re.compile(_fuzzy_regex(snippet), re.DOTALL)
    m = pat.search(region_text)
    if not m:
        head3 = "\n".join(snippet.splitlines()[:3])
        if head3.strip():
            pat2 = re.compile(_fuzzy_regex(head3), re.DOTALL)
            m = pat2.search(region_text)
    if not m:
        logger.error(f"Tool '{tool}': anon snippet not found in file.")
        return None

    hit_start = region_start + m.start()

    # scan to find arrow/lambda then its following '{'
    i = hit_start
    total = len(text)
    in_s = in_d = in_t = in_line = in_block = False
    esc = False
    saw_token = False
    tpl_ok = (lang_name in ("javascript","typescript","tsx"))

    def ahead(s: str, at: int) -> bool:
        return text.startswith(s, at)

    while i < total:
        ch = text[i]

        # comments
        if not (in_s or in_d or in_t):
            if not in_block and not in_line and ahead("//", i):
                in_line = True; i += 2; continue
            if not in_block and not in_line and ahead("/*", i):
                in_block = True; i += 2; continue
            if in_line:
                if ch == "\n": in_line = False
                i += 1; continue
            if in_block:
                if ahead("*/", i): in_block = False; i += 2; continue
                i += 1; continue

        # strings
        if not in_d and not in_t and ch == "'" and not in_s:
            if not esc: in_s = True
            i += 1; esc = False; continue
        if in_s:
            if ch == "\\": esc = not esc
            elif ch == "'" and not esc: in_s = False; esc = False
            else: esc = False
            i += 1; continue
        if not in_s and not in_t and ch == '"' and not in_d:
            if not esc: in_d = True
            i += 1; esc = False; continue
        if in_d:
            if ch == "\\": esc = not esc
            elif ch == '"' and not esc: in_d = False; esc = False
            else: esc = False
            i += 1; continue
        if tpl_ok and not in_s and not in_d and ch == '`' and not in_t:
            in_t = True; i += 1; esc = False; continue
        if in_t:
            if ch == "\\": esc = not esc; i += 1; continue
            if ch == '`' and not esc: in_t = False; esc = False; i += 1; continue
            esc = False; i += 1; continue

        # arrow/lambda tokens
        if not saw_token:
            if tpl_ok and ahead("=>", i):
                saw_token = True; i += 2; continue
            if ahead("->", i):  # Java/C#
                saw_token = True; i += 2; continue
            if ahead("function", i) or ahead("func", i):  # PHP/Go/Swift
                saw_token = True; i += 1; continue
            if ch == '|' and lang_name == "rust":
                saw_token = True; i += 1; continue
            if ch == '{' and lang_name == "kotlin":
                # Kotlin lambda often starts with this '{'
                body_open = i
                saw_token = True
        # take first '{' AFTER token as body
        if saw_token and ch == '{':
            body_open = i
            break

        i += 1

    if not saw_token:
        # fallback: first '{' after hit_start
        j = hit_start
        while j < total and text[j] != '{':
            j += 1
        if j >= total or text[j] != '{':
            logger.error(f"Tool '{tool}': cannot find body start after anon snippet.")
            return None
        body_open = j

    # match braces to get body end
    def brace_window(open_idx: int) -> Optional[int]:
        depth = 0; j = open_idx
        in_s2 = in_d2 = in_t2 = in_line2 = in_block2 = False; esc2 = False
        while j < total:
            c2 = text[j]
            if not (in_s2 or in_d2 or in_t2):
                if not in_block2 and not in_line2 and text.startswith("//", j):
                    in_line2 = True; j += 2; continue
                if not in_block2 and not in_line2 and text.startswith("/*", j):
                    in_block2 = True; j += 2; continue
                if in_line2:
                    if c2 == "\n": in_line2 = False
                    j += 1; continue
                if in_block2:
                    if text.startswith("*/", j): in_block2 = False; j += 2; continue
                    j += 1; continue
            if not in_d2 and not in_t2 and c2 == "'" and not in_s2:
                if not esc2: in_s2 = True
                j += 1; esc2 = False; continue
            if in_s2:
                if c2 == "\\": esc2 = not esc2
                elif c2 == "'" and not esc2: in_s2 = False; esc2 = False
                else: esc2 = False
                j += 1; continue
            if not in_s2 and not in_t2 and c2 == '"' and not in_d2:
                if not esc2: in_d2 = True
                j += 1; esc2 = False; continue
            if in_d2:
                if c2 == "\\": esc2 = not esc2
                elif c2 == '"' and not esc2: in_d2 = False; esc2 = False
                else: esc2 = False
                j += 1; continue
            if tpl_ok and not in_s2 and not in_d2 and c2 == '`' and not in_t2:
                in_t2 = True; j += 1; esc2 = False; continue
            if in_t2:
                if c2 == "\\": esc2 = not esc2; j += 1; continue
                if c2 == '`' and not esc2: in_t2 = False; esc2 = False; j += 1; continue
                esc2 = False; j += 1; continue

            if c2 == '{':
                depth += 1
            elif c2 == '}':
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return None

    end_byte = brace_window(body_open)
    if end_byte is None:
        logger.error(f"Tool '{tool}': unmatched braces for anon block.")
        return None

    # keep context from snippet start; but only collect calls within true body to avoid param destructuring noise
    start_byte = hit_start
    code = text[start_byte:end_byte]

    fe = FuncEntry(
        func_id=mk_func_id(file_rel, f"<block_{tool}>", start_line or 1),
        file_rel=file_rel,
        file_abs=abs_str(p),
        name=f"<block_{tool}>",
        line=start_line or 1,
        start_byte=start_byte,
        end_byte=end_byte,
        code=code,
        lang=LANGUAGE_MAPPING[ext]["name"],
    )
    fe.calls = _collect_calls_in_window(LANGUAGE_MAPPING[ext]["name"], text, ts_manager, body_open, end_byte, logger)
    logger.info(f"Tool '{tool}': anon block built (improved) with {len(fe.calls)} calls.")
    return fe



def build_entry_from_hint(tool: str, hint: Dict[str, Any], root: Path,
                          ts_manager: TreeSitterManager, logger: logging.Logger) -> Optional[FuncEntry]:
    file_rel = hint.get("file_rel") or hint.get("file") or ""
    if not file_rel:
        logger.error(f"Tool '{tool}': No file in hint.")
        return None
    ext = Path(file_rel).suffix.lower()
    lang_name = LANGUAGE_MAPPING.get(ext, {}).get("name", "")
    snippet = hint.get("snippet") or hint.get("code_block") or ""

    kind = classify_hint_snippet(snippet, lang_name)
    logger.info(f"Tool '{tool}': hint classified as {kind}.")

    if kind == "switch_case":
        return build_entry_from_switch_case(tool, hint, root, ts_manager, logger)
    if kind == "anon_block":
        return build_entry_from_anon_block(tool, hint, root, ts_manager, logger)
    if kind == "function":
        return build_entry_from_hint_function(tool, hint, root, ts_manager, logger)

    # unknown: try anon first, then function
    fe = build_entry_from_anon_block(tool, hint, root, ts_manager, logger)
    if fe: return fe
    return build_entry_from_hint_function(tool, hint, root, ts_manager, logger)


def analyze_project(project_dir: Path) -> str:
    # --- Setup Per-Project Logging ---
    project_name = project_dir.name  # Use directory name as logger name
    logger = logging.getLogger(project_name)
    logger.setLevel(logging.DEBUG)  # Set desired level (DEBUG for max detail)

    # Prevent duplicate handlers if function is called multiple times (e.g., in tests)
    if not logger.handlers:
        # Console Handler (INFO level)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch_formatter = logging.Formatter('%(name)s:%(levelname)s: %(message)s')
        ch.setFormatter(ch_formatter)
        logger.addHandler(ch)

        # File Handler (DEBUG level)
        try:
            log_file_path = project_dir / "analysis.log"
            fh = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')  # Overwrite log each run
            fh.setLevel(logging.DEBUG)
            fh_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
            fh.setFormatter(fh_formatter)
            logger.addHandler(fh)
        except Exception as log_e:
            # Log error using root logger if project logger setup failed
            root_logger.error(f"Failed to set up file logging for project '{project_name}': {log_e}")
            # Continue with console logging only

    logger.info(f"--- Starting analysis for project: {project_name} ---")
    logger.debug(f"Project directory: {project_dir.resolve()}")
    logger.debug(f"Max call chain depth: {MAX_DEPTH}")
    logger.debug(f"Max workers (if applicable): {MAX_WORKERS}")

    # Initialize TreeSitterManager (logs its own progress)
    try:
        ts_manager = TreeSitterManager()
    except Exception as e:
        logger.critical(f"Could not initialize TreeSitterManager. Error: {e}", exc_info=True)
        # Clean up handlers before returning
        for handler in logger.handlers[:]: handler.close(); logger.removeHandler(handler)
        return f"[FATAL-INIT-ERROR] {project_name}: Could not initialize TreeSitterManager. Error: {e}"

    # --- Identify Project and Refined JSON Path ---
    jsonName = ''
    try:
        # Robustly find the JSON name (assuming format 'prefix__jsonName')
        items = project_name.split('__')
        if len(items) >= 2:
            jsonName = items[1]
            logger.debug(f"Determined JSON base name: {jsonName}")
        else:
            logger.error(f"Project directory name '{project_name}' doesn't follow expected 'prefix__jsonName' format.")
            # Clean up handlers and return
            for handler in logger.handlers[:]: handler.close(); logger.removeHandler(handler)
            return f"[ERROR] {project_name}: Invalid project name format."
        jsonName = project_name
        refined_json = project_dir / "output_refined_v1" / f"{jsonName}.json"
        logger.debug(f"Looking for refined JSON at: {refined_json}")
        if not refined_json.is_file():
            msg = f"[skip] {project_name}: no refined JSON found at output_refined_v1/{jsonName}.json"
            logger.warning(msg)
            for handler in logger.handlers[:]: handler.close(); logger.removeHandler(handler)
            return msg
    except Exception as e:
        logger.error(f"Error determining or checking refined JSON path: {e}", exc_info=True)
        for handler in logger.handlers[:]: handler.close(); logger.removeHandler(handler)
        return f"[ERROR] {project_name}: Could not process refined JSON path."

    # --- Load Entry Hints ---
    hints = load_entry_hints_from_refined_json(project_dir, refined_json, logger)  # Pass logger
    if not hints:
        msg = f"[skip] {project_name}: no valid hints loaded from refined_json"
        logger.warning(msg)
        for handler in logger.handlers[:]: handler.close(); logger.removeHandler(handler)
        return msg
    # logger.info(f"Found {len(hints)} tools with resolved handlers.") # Already logged by load_entry_hints

    # --- Build Function Index ---
    logger.info("Building function index for the entire project...")
    try:
        files = iter_code_files(project_dir)  # iter_code_files uses logging
        # Pass the project-specific logger to build_function_index
        index = build_function_index(project_dir, files, ts_manager, logger)
        name_lut = build_name_lookup(index)  # build_name_lookup uses logging
        # logger.info(f"Indexed {len(index)} functions across {len(files)} files.") # Logged by build_function_index
    except Exception as e:
        logger.critical(f"Failed during function indexing: {e}", exc_info=True)
        for handler in logger.handlers[:]: handler.close(); logger.removeHandler(handler)
        return f"[FATAL-INDEX-ERROR] {project_name}: Error during function indexing. See logs."

    # --- Process Tools and Build Call Chains ---
    tools_map, call_chains, unresolved = {}, {}, {}
    processed_tools = 0
    failed_tools = 0
    for tool, hint in hints.items():

        logger.info(f"--- Processing tool: {tool} ---")
        try:
            # Pass logger to hint builder
            fe = build_entry_from_hint(tool, hint, project_dir, ts_manager, logger)
            if not fe:
                logger.error(f"Failed to build entry for tool '{tool}'. Adding to unresolved.")
                unresolved[tool] = "failed to build entry from slice hint (AST)"
                failed_tools += 1
                continue

            # Ensure entry is in index (should be if built successfully, but safe check)
            if fe.func_id not in index:
                index[fe.func_id] = fe
                # Update name_lut if entry was newly added
                try:
                    base_name = fe.name.split('.')[-1].split('::')[-1]
                    name_lut.setdefault(base_name, []).append(fe.func_id)
                    logger.debug(f"Added new entry '{fe.func_id}' to index and lookup table.")
                except Exception as lut_e:
                    logger.warning(f"Error adding new entry '{fe.func_id}' to lookup table: {lut_e}")

            tools_map[tool] = f"{fe.file_abs}::{fe.name}"  # Use absolute path
            logger.debug(f"Building call chain starting from '{fe.func_id}'")
            # Pass logger to call chain builder
            obj = build_nested_calls(fe, index, name_lut, project_dir, MAX_DEPTH, seen={fe.func_id}, logger=logger)
            call_chains[tool] = [obj]  # Wrap in list as per original structure
            logger.info(f"Successfully processed tool '{tool}'. Chain depth might be limited by MAX_DEPTH.")
            processed_tools += 1
        except Exception as tool_e:
            logger.error(f"Unexpected error processing tool '{tool}': {tool_e}", exc_info=True)
            unresolved[tool] = f"runtime error during processing: {tool_e}"
            failed_tools += 1
            # Continue to next tool

    # --- Finalize and Save Results ---
    logger.info(f"Finished processing tools. Succeeded: {processed_tools}, Failed/Unresolved: {failed_tools}")
    result = {
        "project": project_name,
        "tools": tools_map,
        "call_chains": call_chains,
        "unresolved_tools": unresolved,
        "metrics": {
            "entry_mode": "refined_json_v1",
            "hint_file": rel(project_dir, refined_json),
            "total_indexed_functions": len(index),
            # Add more metrics? e.g., max_chain_depth_found?
        }
    }

    try:
        out_path = project_dir / "call_chains.json"
        logger.info(f"Writing results to {out_path}...")
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        msg = f"[ok] {project_name}: tools={len(tools_map)} unresolved={len(unresolved)} -> {out_path.name}"
        logger.info(f"--- Analysis finished successfully for project: {project_name}. ---")
    except Exception as write_e:
        logger.error(f"Failed to write results JSON to {out_path}: {write_e}", exc_info=True)
        msg = f"[ERROR] {project_name}: Failed to write results JSON. See logs."

    # --- Clean up logger handlers for this project ---
    logger.info("Cleaning up project logger handlers.")
    for handler in logger.handlers[:]:
        try:
            handler.flush()
            handler.close()
        except Exception as close_e:
            # Use root logger for this potential error during cleanup
            root_logger.error(f"Error closing handler for {project_name}: {close_e}")
        finally:
            logger.removeHandler(handler)

    return msg


# ====================== Main Execution ======================
def main():
    # Use root_logger for main execution flow messages
    logger = logging.getLogger("main")
    logger.info("Starting main execution...")

    root = BASE_CODE_DIR
    if not root.is_dir():  # Check if it's a directory
        logger.critical(f"Base directory not found or not a directory: {root}")
        return

    logger.info("Initializing global TreeSitterManager (checking grammars)...")
    try:
        # This initial build in the main process is crucial.
        # Errors will be logged internally by TreeSitterManager
        TreeSitterManager()
        logger.info("Global TreeSitterManager initialized successfully.")
    except Exception as e:
        # Error likely already logged, but add critical message here
        logger.critical(f"Failed to initialize the global TreeSitterManager: {e}", exc_info=True)
        logger.critical("Please ensure a C/C++ compiler is installed and tree-sitter packages are installed correctly.")
        return

    # --- Find Target Projects ---
    targets = []
    logger.info(f"Scanning for target projects in '{root}'...")
    try:
        for p in root.iterdir():
            if not p.is_dir():
                logger.debug(f"Skipping non-directory item: {p.name}")
                continue
            logger.debug(f"Checking potential project directory: {p.name}")
            try:
                items = p.name.split('__')
                if len(items) < 2:
                    logger.warning(f"Skipping directory with unexpected name format: {p.name}")
                    continue
                json_base_name = items[1]
                json_base_name = p.name
                candidate = p / "output_refined_v1" / f"{json_base_name}.json"
                logger.debug(f"  Checking for hint file: {candidate}")
                if candidate.is_file():
                    logger.info(f"Found target project with hint file: {p.name}")
                    targets.append(p)
                # else: logger.debug(f"  Hint file not found.")
            except Exception as check_e:
                logger.error(f"Error while checking directory {p.name}: {check_e}", exc_info=True)
    except Exception as iter_e:
        logger.critical(f"Error iterating through base directory '{root}': {iter_e}", exc_info=True)
        return

    if not targets:
        logger.info("No projects with required entry point JSONs found to analyze.")
        return

    # --- Multiprocessing ---
    logger.info(f"Analyzing {len(targets)} projects using up to {MAX_WORKERS} workers...")
    results = []
    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as ex:
        # Submit tasks
        futs = {ex.submit(analyze_project, proj): proj.name for proj in targets}
        logger.info(f"Submitted {len(futs)} analysis tasks.")

        # Collect results as they complete
        for fut in as_completed(futs):
            proj_name = futs[fut]
            try:
                result_msg = fut.result()
                logger.info(f"Worker finished for '{proj_name}'. Result: {result_msg}")
                results.append(result_msg)
            except Exception as e:
                logger.critical(f"FATAL WORKER ERROR for project '{proj_name}': {e}", exc_info=True)
                # Optionally capture the error message to report it
                results.append(f"[FATAL-WORKER-ERROR] {proj_name}: {e}")
                # Log the full traceback from the worker if possible (might not always propagate)
                # traceback.print_exc() # This would print in the main process

    logger.info("--- Analysis Run Summary ---")
    ok_count = sum(1 for r in results if r.startswith("[ok]"))
    skip_count = sum(1 for r in results if r.startswith("[skip]"))
    error_count = sum(1 for r in results if "[ERROR]" in r or "[FATAL" in r)
    logger.info(f"Total projects attempted: {len(targets)}")
    logger.info(f"  Succeeded: {ok_count}")
    logger.info(f"  Skipped: {skip_count}")
    logger.info(f"  Errors/Failed: {error_count}")
    logger.info("--------------------------")
    logger.info("Main execution finished.")


if __name__ == "__main__":
    # Multiprocessing setup for Windows
    if sys.platform == "win32":
        # Check if already set by environment or parent process
        if multiprocessing.get_start_method(allow_none=True) is None:
            try:
                multiprocessing.set_start_method("spawn", force=True)
                root_logger.info("Set multiprocessing start method to 'spawn' for Windows.")
            except RuntimeError as re:
                root_logger.warning(f"Could not set multiprocessing start method (may already be set): {re}")
    main()