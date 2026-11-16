"""
===============================================================================
PowerShell to Tenable .Audit File Generator
===============================================================================
Reads the PowerShell scripts (.ps1) from the powershell/ folder, converts them
to Base64 (UTF-16-LE) and consolidates them into a single .audit file, written
to the audits/ folder.

Check mode (chosen automatically, the scripts themselves are never modified):
  - EVALUATION    : the script contains "Non-Compliant" somewhere (it can fail).
                    Tenable reports PASSED if the output contains
                    "Check status: Compliant" and FAILED otherwise.
  - INFORMATIONAL : the script never writes "Non-Compliant" (it only reports data).
                    Tenable shows the output as INFO, without a verdict.
  The mode can be forced with --info / --eval (see examples).

Evaluation regex: "Check status ?: ?Compliant"
  - accepts both "Check status: Compliant" and "Check Status : Compliant"
    (AUDIT_POWERSHELL comparisons are case-insensitive)
  - no ^ anchor, so the line is found even if the script prints something before it
  - does not match "Check status: Non-Compliant", because ": " is followed by "Non-"

Examples (from the repository root):
  python audit_convert.py -n "Windows 11 Enterprise"
      -> reads powershell/*.ps1, writes audits/Windows_11_Enterprise.audit
  python audit_convert.py -n "Windows 11 Enterprise" --info admins.ps1 --eval other.ps1
      -> forces the mode of specific scripts
  python audit_convert.py -n "Test" -d C:\\other\\folder
      -> reads the .ps1 files from another folder (output still goes to audits/)
===============================================================================
"""

import argparse
import base64
import os
import re

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PS_DIR = os.path.join(REPO_DIR, "powershell")
AUDITS_DIR = os.path.join(REPO_DIR, "audits")

PASS_REGEX = "Check status ?: ?Compliant"
STATUS_LINE_RE = re.compile(r"check status\s*:", re.IGNORECASE)
NON_COMPLIANT_RE = re.compile(r"non-compliant", re.IGNORECASE)
PS_LIMIT = 8192  # limit documented by Tenable for PowerShell scripts in .audit files

# Header line: "# <Author>  <date>  <Description>", e.g.
#   # G. MOURNETAS     04/08/2026   'Ensure "Do not display the lock screen" is set to ...'
# The author may contain spaces and dots; the date is the anchor that separates the fields.
HEADER_RE = re.compile(r"^#+\s*(?P<author>\S.*?)\s+(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<desc>\S.*?)\s*$")
HEADER_SCAN_LINES = 20  # only look at the top of the script

AUDIT_WRAPPER_TEMPLATE = """<check_type:"Windows" version:"2">
<group_policy:"{group_policy_name}">

{checks_body}
</group_policy>
</check_type>
"""

CHECK_HEADER_TEMPLATE = """# ============================================================
# CHECK {check_num}: {check_name}  [{mode}]
# ============================================================"""

EVAL_ITEM_TEMPLATE = """<custom_item>
  type: AUDIT_POWERSHELL
  description: "{check_name}"
  value_type: POLICY_TEXT
  value_data: "{pass_regex}"
  check_type: CHECK_REGEX
  powershell_args: '{encoded_payload}'
  ps_encoded_args: YES
</custom_item>"""

INFO_ITEM_TEMPLATE = """<custom_item>
  type: AUDIT_POWERSHELL
  description: "{check_name}"
  value_type: POLICY_TEXT
  value_data: ""
  powershell_args: '{encoded_payload}'
  ps_encoded_args: YES
  only_show_cmd_output: YES
</custom_item>"""


def read_script(script_path):
    with open(script_path, "r", encoding="utf-8") as file:
        return file.read()


def powershell_to_base64(script_content):
    """UTF-16-LE + Base64: the format expected by powershell.exe -EncodedCommand."""
    return base64.b64encode(script_content.encode("utf-16-le")).decode("ascii")


def extract_description(script_content):
    """
    Returns the description from the first header entry (the original one, if the
    header has several changelog lines), or None if no header line is found.
    Surrounding single quotes are removed: 'Ensure X' -> Ensure X
    """
    for line in script_content.splitlines()[:HEADER_SCAN_LINES]:
        match = HEADER_RE.match(line.strip())
        if match:
            desc = match.group("desc")
            if len(desc) >= 2 and desc[0] == desc[-1] == "'":
                desc = desc[1:-1].strip()
            return desc
    return None


def detect_mode(script_content):
    """Evaluation if the script can write Non-Compliant, informational otherwise."""
    return "EVAL" if NON_COMPLIANT_RE.search(script_content) else "INFO"


def format_output_filename(name):
    """
    Transforms the group policy name into a clean filename:
    - Strips leading and trailing whitespace
    - Replaces consecutive whitespace characters with a single underscore '_'
    - Sanitizes invalid filesystem characters
    """
    cleaned_name = name.strip()
    filename = re.sub(r"\s+", "_", cleaned_name)
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
    return filename


def escape_audit_string(text):
    """Escapes backslashes and double quotes for a double-quoted .audit string."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def get_ps1_files_from_dir(directory_path):
    """Returns the sorted paths of all .ps1 files in the folder (case-insensitive)."""
    if not os.path.isdir(directory_path):
        print(f"Error: Directory '{directory_path}' does not exist or is not a directory.")
        return []
    ps1_files = [
        os.path.join(directory_path, entry)
        for entry in os.listdir(directory_path)
        if os.path.isfile(os.path.join(directory_path, entry)) and entry.lower().endswith(".ps1")
    ]
    ps1_files.sort()  # deterministic check numbering
    return ps1_files


def normalize_names(names):
    """Accepts --info admins or --info admins.ps1 (case-insensitive)."""
    result = set()
    for n in names or []:
        n = n.lower()
        result.add(n if n.endswith(".ps1") else n + ".ps1")
    return result


def generate_consolidated_audit(group_policy_name, directory_path, force_info, force_eval):
    """Reads all .ps1 files from the folder and consolidates them into a single .audit file."""
    ps1_files = get_ps1_files_from_dir(directory_path)
    if not ps1_files:
        print(f"No .ps1 files found in '{directory_path}'. Nothing to generate.")
        return

    print(f"Found {len(ps1_files)} PowerShell script(s) in '{directory_path}'. Processing...\n")

    found_names = {os.path.basename(p).lower() for p in ps1_files}
    for name in sorted((force_info | force_eval) - found_names):
        print(f"  WARNING: '{name}' was given in --info/--eval but does not exist in the folder.")

    check_blocks, warnings = [], 0
    seen_descriptions = {}
    counts = {"EVAL": 0, "INFO": 0}

    for index, ps1_path in enumerate(ps1_files, start=1):
        file_name = os.path.basename(ps1_path)
        script_name = os.path.splitext(file_name)[0]
        script_content = read_script(ps1_path)

        if file_name.lower() in force_info:
            mode, how = "INFO", "forced"
        elif file_name.lower() in force_eval:
            mode, how = "EVAL", "forced"
        else:
            mode, how = detect_mode(script_content), "auto"
        counts[mode] += 1

        description = extract_description(script_content)

        print(f"[{index}/{len(ps1_files)}] {file_name} -> CHECK {index}: "
              f"{'EVALUATION' if mode == 'EVAL' else 'INFORMATIONAL'} ({how})")
        if description:
            print(f"      Description: {description}")
        else:
            description = script_name
            print(f"      WARNING: no header description found, using the file name: {description}")
            warnings += 1

        if description in seen_descriptions:
            print(f"      WARNING: same description as {seen_descriptions[description]} "
                  f"(Tenable derives the check ID from the description).")
            warnings += 1
        seen_descriptions.setdefault(description, file_name)

        encoded_payload = powershell_to_base64(script_content)

        if not STATUS_LINE_RE.search(script_content):
            print("      WARNING: no 'Check status :' line found in the script.")
            warnings += 1
        if mode == "EVAL" and not re.search(r"check status\s*:\s*compliant", script_content, re.IGNORECASE):
            print("      WARNING: evaluation mode but the script never writes 'Compliant' -> always FAILED.")
            warnings += 1
        if len(encoded_payload) > PS_LIMIT:
            print(f"      WARNING: encoded payload has {len(encoded_payload)} characters "
                  f"(Tenable limit for PowerShell scripts is {PS_LIMIT}).")
            warnings += 1

        header = CHECK_HEADER_TEMPLATE.format(
            check_num=index, check_name=file_name,
            mode="EVALUATION" if mode == "EVAL" else "INFORMATIONAL")
        template = EVAL_ITEM_TEMPLATE if mode == "EVAL" else INFO_ITEM_TEMPLATE
        item = template.format(
            check_name=escape_audit_string(description),
            pass_regex=PASS_REGEX,
            encoded_payload=encoded_payload)
        check_blocks.append(header + "\n" + item)

    final_audit_content = AUDIT_WRAPPER_TEMPLATE.format(
        group_policy_name=escape_audit_string(group_policy_name.strip()),
        checks_body="\n\n".join(check_blocks))

    os.makedirs(AUDITS_DIR, exist_ok=True)
    final_path = os.path.join(AUDITS_DIR, f"{format_output_filename(group_policy_name)}.audit")
    with open(final_path, "w", encoding="utf-8") as out_file:
        out_file.write(final_audit_content)

    print(f"\nSuccess! '{final_path}' created with {len(check_blocks)} check(s): "
          f"{counts['EVAL']} evaluation, {counts['INFO']} informational.")
    if warnings:
        print(f"{warnings} warning(s) - see above.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compiles the .ps1 files from powershell/ into a single Tenable .audit file in audits/.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("-n", "--name", required=True,
                        help="Group Policy name, also used as the output file name (e.g. 'Windows 11 Enterprise')")
    parser.add_argument("-d", "--dir", default=DEFAULT_PS_DIR,
                        help="Folder with the .ps1 files (default: powershell/)")
    parser.add_argument("--info", nargs="+", metavar="SCRIPT",
                        help="Force these scripts to informational mode")
    parser.add_argument("--eval", nargs="+", metavar="SCRIPT",
                        help="Force these scripts to evaluation mode")
    args = parser.parse_args()

    force_info, force_eval = normalize_names(args.info), normalize_names(args.eval)
    both = force_info & force_eval
    if both:
        parser.error(f"script(s) in both --info and --eval: {', '.join(sorted(both))}")

    generate_consolidated_audit(args.name, args.dir, force_info, force_eval)
