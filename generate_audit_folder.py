"""
===============================================================================
PowerShell to Tenable .Audit File Generator
===============================================================================
This script scans a directory for PowerShell scripts (.ps1), converts their 
contents into Base64 (UTF-16-LE), and consolidates them into a single Tenable 
.audit file.

Usage Examples:

1. Process a directory of scripts:
   python generate_audit.py -n "Windows 11 Enterprise" -d ./scripts
   (Output file: Windows_11_Enterprise.audit)

2. Using absolute path:
   python generate_audit.py -n "Windows 11 Security Baseline" -d "C:\\Audits\\PowerShellChecks"
===============================================================================
"""

import base64
import argparse
import os
import re

# Embedded Tenable Audit Wrapper Template
AUDIT_WRAPPER_TEMPLATE = """<check_type:"Windows" version:"2">
<group_policy:"{group_policy_name}">

{checks_body}
</group_policy>
</check_type>
"""

# Embedded Individual Check Item Template
CHECK_ITEM_TEMPLATE = """# ============================================================
# CHECK {check_num}: {check_name}
# ============================================================
<custom_item>
  type: AUDIT_POWERSHELL
  description: "{check_name}"
  value_type: POLICY_TEXT
  value_data: ""
  powershell_args: '{encoded_payload}'
  ps_encoded_args: YES
  only_show_cmd_output: YES
</custom_item>"""


def powershell_to_base64(script_path):
    """Reads the .ps1 script and converts it to Base64 (UTF-16-LE)."""
    with open(script_path, 'r', encoding='utf-8') as file:
        script_content = file.read()
    
    encoded_bytes = script_content.encode('utf-16-le')
    return base64.b64encode(encoded_bytes).decode('utf-8')


def format_output_filename(name):
    """
    Transforms the group policy name into a clean filename:
    - Strips leading and trailing whitespaces
    - Replaces consecutive whitespace characters with a single underscore '_'
    - Sanitizes invalid filesystem characters
    """
    cleaned_name = name.strip()
    filename = re.sub(r'\s+', '_', cleaned_name)
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    return filename


def get_ps1_files_from_dir(directory_path):
    """
    Scans the specified directory and returns sorted paths of all .ps1 files.
    Strictly filters for .ps1 files only (case-insensitive).
    """
    if not os.path.isdir(directory_path):
        print(f"Error: Directory '{directory_path}' does not exist or is not a directory.")
        return []

    ps1_files = []
    for entry in os.listdir(directory_path):
        full_path = os.path.join(directory_path, entry)
        if os.path.isfile(full_path) and entry.lower().endswith(".ps1"):
            ps1_files.append(full_path)

    # Sort files alphabetically to ensure deterministic check numbering
    ps1_files.sort()
    return ps1_files


def generate_consolidated_audit(group_policy_name, directory_path):
    """Reads all .ps1 files from the directory and consolidates them into a single .audit file."""
    ps1_files = get_ps1_files_from_dir(directory_path)

    if not ps1_files:
        print(f"No .ps1 files found in '{directory_path}'. Nothing to generate.")
        return

    print(f"Found {len(ps1_files)} PowerShell script(s) in '{directory_path}'. Processing...\n")

    check_blocks = []
    for index, ps1_path in enumerate(ps1_files, start=1):
        script_name = os.path.splitext(os.path.basename(ps1_path))[0]
        print(f"[{index}/{len(ps1_files)}] Converting '{os.path.basename(ps1_path)}' -> CHECK {index}: {script_name}")
        
        encoded_payload = powershell_to_base64(ps1_path)

        block = CHECK_ITEM_TEMPLATE.format(
            check_num=index,
            check_name=script_name,
            encoded_payload=encoded_payload
        )
        check_blocks.append(block)

    # Join all check blocks with a blank line between them
    checks_body = "\n\n".join(check_blocks)

    # Inject into main wrapper template
    final_audit_content = AUDIT_WRAPPER_TEMPLATE.format(
        group_policy_name=group_policy_name.strip(),
        checks_body=checks_body
    )

    # Derive output filename
    base_filename = format_output_filename(group_policy_name)
    final_filename = f"{base_filename}.audit"

    with open(final_filename, 'w', encoding='utf-8') as out_file:
        out_file.write(final_audit_content)

    print(f"\nSuccess! Consolidated audit file '{final_filename}' created with {len(check_blocks)} check(s).")


# --- Script Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scans a folder for .ps1 files and compiles them into a single Tenable .audit file."
    )
    parser.add_argument(
        "-n", "--name",
        required=True,
        help="Group Policy name (e.g., 'Windows 11 Enterprise')"
    )
    parser.add_argument(
        "-d", "--dir",
        required=True,
        help="Path to directory containing the .ps1 files"
    )

    args = parser.parse_args()
    generate_consolidated_audit(args.name, args.dir)