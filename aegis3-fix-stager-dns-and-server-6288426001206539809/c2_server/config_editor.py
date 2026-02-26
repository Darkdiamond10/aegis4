import re
import os

# ── Resolve config path relative to this script's location ────────────────
# This ensures the config editor works regardless of the working directory.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "common", "config.h")

def read_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[!] Config not found at: {CONFIG_PATH}")
        return None

def get_aa_settings():
    content = read_config()
    if not content:
        return {}

    settings = {}

    # Regex to find defines that start with AEGIS_AA_ENABLE_
    # They might be commented out
    pattern = r"(//)?\s*#define\s+(AEGIS_AA_ENABLE_\w+)"

    matches = re.finditer(pattern, content)
    for match in matches:
        is_commented = match.group(1) is not None
        key = match.group(2)
        settings[key] = not is_commented

    return settings

def toggle_setting(key, enable):
    content = read_config()
    if not content:
        return False

    # Create the replacement pattern
    # We want to find the line with this key
    # It might be: "#define KEY" or "// #define KEY" or "//#define KEY"

    escaped_key = re.escape(key)
    pattern = r"((?://)?\s*#define\s+" + escaped_key + r")"

    match = re.search(pattern, content)
    if not match:
        return False

    if enable:
        new_line = f"#define {key}"
    else:
        new_line = f"// #define {key}"

    content = re.sub(pattern, new_line, content)

    with open(CONFIG_PATH, "w") as f:
        f.write(content)

    return True

def get_config_value(key):
    content = read_config()
    if not content:
        return None

    escaped_key = re.escape(key)
    pattern = r"#define\s+" + escaped_key + r"\s+(.+)"
    match = re.search(pattern, content)

    if match:
        val = match.group(1).strip()
        # Remove comments if present
        if "/*" in val:
            val = val.split("/*")[0].strip()
        # Remove line continuation markers
        if val.endswith("\\"):
            val = val[:-1].strip()
        # Remove surrounding quotes for string values
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        return val
    return None

def set_config_value(key, value):
    content = read_config()
    if not content:
        return False

    escaped_key = re.escape(key)
    # Find the line, capturing comments at end if any
    pattern = r"(#define\s+" + escaped_key + r"\s+)(.+?)(\s*/\*.*)?$"

    match = re.search(pattern, content, re.MULTILINE)
    if not match:
        return False

    prefix = match.group(1)

    # Simple replace — preserve trailing comment if it existed
    new_line = f"{prefix}{value}"
    if match.group(3):
        new_line += f" {match.group(3)}"

    content = content.replace(match.group(0), new_line)

    with open(CONFIG_PATH, "w") as f:
        f.write(content)

    return True
