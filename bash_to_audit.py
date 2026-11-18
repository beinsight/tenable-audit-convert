"""
===============================================================================
Bash to Tenable .Audit File Generator
===============================================================================
Reads the bash scripts (.sh) from the bash/ folder, converts them to Base64
(UTF-8) and consolidates them into a single .audit file, written to the
audits/ folder.

Each script becomes a CMD_EXEC check (check_type "Unix") that runs:
    echo <base64> | base64 -d | bash
Base64 only uses [A-Za-z0-9+/=], so nothing needs escaping inside the .audit,
and the script runs on the target exactly as written. "| bash" is explicit
because the scripts use bash syntax ([[ ]]) and Nessus may run cmd with sh.

Check mode (chosen automatically, the scripts themselves are never modified):
  - EVALUATION    : the script contains "Non-Compliant" somewhere (it can fail).
                    Tenable reports PASSED if the output contains
                    "Check status: Compliant" and FAILED otherwise.
  - INFORMATIONAL : the script never writes "Non-Compliant" (it only reports data).
                    CMD_EXEC has no equivalent of only_show_cmd_output, so the
                    check uses expect ".*" (always PASSED, output shown) and the
                    description is prefixed with "[INFO]" to make that clear.
  The mode can be forced with --info / --eval (see examples).

Evaluation regex: "Check status ?: ?Compliant"
  - accepts both "Check status: Compliant" and "Check Status : Compliant"
    (match_case is left at its default NO, so the comparison is case-insensitive)
  - no ^ anchor, so the line is found even if the script prints something before it
  - does not match "Check status: Non-compliant", because ": " is followed by "Non-"

Line endings: Windows line endings (CRLF) are converted to LF before encoding,
because bash treats the "\\r" as part of each command and the script breaks.

Examples (from the repository root):
  python bash_to_audit.py -n "Linux RHEL"
      -> reads bash/*.sh, writes audits/Linux_RHEL.audit
  python bash_to_audit.py -n "Linux RHEL" --info list_users.sh --eval other.sh
      -> forces the mode of specific scripts
  python bash_to_audit.py -n "Test" -d /other/folder
      -> reads the .sh files from another folder (output still goes to audits/)
===============================================================================
"""

import argparse
import base64
import os
import re

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASH_DIR = os.path.join(REPO_DIR, "bash")
AUDITS_DIR = os.path.join(REPO_DIR, "audits")

PASS_REGEX = "Check status ?: ?Compliant"
INFO_REGEX = ".*"
INFO_PREFIX = "[INFO] "
STATUS_LINE_RE = re.compile(r"check status\s*:", re.IGNORECASE)
NON_COMPLIANT_RE = re.compile(r"non-compliant", re.IGNORECASE)
DEFAULT_TIMEOUT = 300  # seconds, same as the Nessus default for CMD_EXEC

# Header line: "# <Author>  <date>  <Description>", e.g.
#   # R. Casagrande  19/08/2025  Ensure X Window System is not installed
# The author may contain spaces and dots; the date is the anchor that separates the fields.
HEADER_RE = re.compile(r"^#+\s*(?P<author>\S.*?)\s+(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<desc>\S.*?)\s*$")
HEADER_SCAN_LINES = 20  # only look at the top of the script

AUDIT_WRAPPER_TEMPLATE = """<check_type:"Unix">

{checks_body}

</check_type>
"""

CHECK_HEADER_TEMPLATE = """# ============================================================
# CHECK {check_num}: {check_name}  [{mode}]
# ============================================================"""

ITEM_TEMPLATE = """<custom_item>
  type          : CMD_EXEC
  description   : "{check_name}"
  cmd           : "echo {encoded_payload} | base64 -d | bash"
  expect        : "{expect_regex}"
  timeout       : "{timeout}"
  dont_echo_cmd : YES
</custom_item>"""


def read_script(script_path):
    """Reads the .sh file and normalizes CRLF line endings to LF."""
    with open(script_path, "r", encoding="utf-8", newline="") as file:
        content = file.read()
    had_crlf = "\r\n" in content
    return content.replace("\r\n", "\n"), had_crlf


def bash_to_base64(script_content):
    """UTF-8 + Base64, decoded on the target with base64 -d."""
    return base64.b64encode(script_content.encode("utf-8")).decode("ascii")


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
    Transforms the policy name into a clean filename:
    - Strips leading and trailing whitespace
    - Replaces consecutive whitespace characters with a single underscore '_'
    - Sanitizes invalid filesystem characters
    """
    cleaned_name = name.strip()
    filename = re.sub(r"\s+", "_", cleaned_name)
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
    return filename


def clean_audit_string(text):
    """
    Makes text safe inside a double-quoted .audit string (description, policy name).
    Double quotes are replaced with single quotes: Tenable does not accept the
    escaped form \\" in these fields, so 'Ensure "X"' becomes 'Ensure 'X''.
    """
    return text.replace('"', "'")


def get_sh_files_from_dir(directory_path):
    """Returns the sorted paths of all .sh files in the folder (case-insensitive)."""
    if not os.path.isdir(directory_path):
        print(f"Error: Directory '{directory_path}' does not exist or is not a directory.")
        return []
    sh_files = [
        os.path.join(directory_path, entry)
        for entry in os.listdir(directory_path)
        if os.path.isfile(os.path.join(directory_path, entry)) and entry.lower().endswith(".sh")
    ]
    sh_files.sort()  # deterministic check numbering
    return sh_files


def normalize_names(names):
    """Accepts --info users or --info users.sh (case-insensitive)."""
    result = set()
    for n in names or []:
        n = n.lower()
        result.add(n if n.endswith(".sh") else n + ".sh")
    return result


def generate_consolidated_audit(policy_name, directory_path, force_info, force_eval, timeout):
    """Reads all .sh files from the folder and consolidates them into a single .audit file."""
    sh_files = get_sh_files_from_dir(directory_path)
    if not sh_files:
        print(f"No .sh files found in '{directory_path}'. Nothing to generate.")
        return

    print(f"Found {len(sh_files)} bash script(s) in '{directory_path}'. Processing...\n")

    found_names = {os.path.basename(p).lower() for p in sh_files}
    for name in sorted((force_info | force_eval) - found_names):
        print(f"  WARNING: '{name}' was given in --info/--eval but does not exist in the folder.")

    check_blocks, warnings = [], 0
    seen_descriptions = {}
    counts = {"EVAL": 0, "INFO": 0}

    for index, sh_path in enumerate(sh_files, start=1):
        file_name = os.path.basename(sh_path)
        script_name = os.path.splitext(file_name)[0]
        script_content, had_crlf = read_script(sh_path)

        if file_name.lower() in force_info:
            mode, how = "INFO", "forced"
        elif file_name.lower() in force_eval:
            mode, how = "EVAL", "forced"
        else:
            mode, how = detect_mode(script_content), "auto"
        counts[mode] += 1

        description = extract_description(script_content)

        print(f"[{index}/{len(sh_files)}] {file_name} -> CHECK {index}: "
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

        if had_crlf:
            print("      NOTE: Windows line endings (CRLF) converted to LF.")
        if not STATUS_LINE_RE.search(script_content):
            print("      WARNING: no 'Check status :' line found in the script.")
            warnings += 1
        if mode == "EVAL" and not re.search(r"check status\s*:\s*compliant", script_content, re.IGNORECASE):
            print("      WARNING: evaluation mode but the script never writes 'Compliant' -> always FAILED.")
            warnings += 1

        header = CHECK_HEADER_TEMPLATE.format(
            check_num=index, check_name=file_name,
            mode="EVALUATION" if mode == "EVAL" else "INFORMATIONAL")
        item = ITEM_TEMPLATE.format(
            check_name=clean_audit_string((INFO_PREFIX if mode == "INFO" else "") + description),
            encoded_payload=bash_to_base64(script_content),
            expect_regex=PASS_REGEX if mode == "EVAL" else INFO_REGEX,
            timeout=timeout)
        check_blocks.append(header + "\n" + item)

    final_audit_content = AUDIT_WRAPPER_TEMPLATE.format(checks_body="\n\n".join(check_blocks))

    os.makedirs(AUDITS_DIR, exist_ok=True)
    final_path = os.path.join(AUDITS_DIR, f"{format_output_filename(policy_name)}.audit")
    with open(final_path, "w", encoding="utf-8", newline="\n") as out_file:
        out_file.write(final_audit_content)

    print(f"\nSuccess! '{final_path}' created with {len(check_blocks)} check(s): "
          f"{counts['EVAL']} evaluation, {counts['INFO']} informational.")
    if warnings:
        print(f"{warnings} warning(s) - see above.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compiles the .sh files from bash/ into a single Tenable .audit file in audits/.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("-n", "--name", required=True,
                        help="Policy name, used as the output file name (e.g. 'Linux RHEL')")
    parser.add_argument("-d", "--dir", default=DEFAULT_BASH_DIR,
                        help="Folder with the .sh files (default: bash/)")
    parser.add_argument("--info", nargs="+", metavar="SCRIPT",
                        help="Force these scripts to informational mode")
    parser.add_argument("--eval", nargs="+", metavar="SCRIPT",
                        help="Force these scripts to evaluation mode")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout per check in seconds (default: {DEFAULT_TIMEOUT})")
    args = parser.parse_args()

    force_info, force_eval = normalize_names(args.info), normalize_names(args.eval)
    both = force_info & force_eval
    if both:
        parser.error(f"script(s) in both --info and --eval: {', '.join(sorted(both))}")

    generate_consolidated_audit(args.name, args.dir, force_info, force_eval, args.timeout)
