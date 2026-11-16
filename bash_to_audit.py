#!/usr/bin/env python3
"""
sh2audit — converte scripts bash de compliance (estilo Qualys / OpenSCAP SCE)
em ficheiros .audit do Tenable (Nessus), usando checks CMD_EXEC.

Convenção esperada nos scripts:
  - cabeçalho com uma linha  "# <Nome>  <dd/mm/aaaa>  <Descrição>"
  - output "Check status: Compliant." quando passa
    (qualquer outro output conta como FAILED no Tenable)

Como funciona:
  O script inteiro é codificado em base64 e colocado no `cmd`:
      echo <base64> | base64 -d | bash
  O base64 só usa [A-Za-z0-9+/=], por isso não há aspas nem barras para
  escapar no .audit, e o script corre byte a byte igual ao original.
  O texto original vai em comentário por cima de cada item, para revisão.

Uso (a partir da raiz do repo):
  python bash_to_audit.py -o Linux_RHEL                 -> lê bash/*.sh, escreve audits/Linux_RHEL.audit
  python bash_to_audit.py bash/bash1.sh -o Teste        -> só um script
  python bash_to_audit.py -o outra/pasta/X.audit        -> caminho explícito, fora de audits/
  python bash_to_audit.py --split -o linux              -> um .audit por script em audits/linux/
"""

import argparse
import base64
import re
import sys
from pathlib import Path

HEADER_RE = re.compile(r"^#\s*\S.*?\s+\d{1,2}/\d{1,2}/\d{4}\s+(?P<desc>\S.*?)\s*$")
REPO_DIR = Path(__file__).resolve().parent   # pasta onde está este script
BASH_DIR = REPO_DIR / "bash"
AUDITS_DIR = REPO_DIR / "audits"
PASS_MARKER = "Check status: Compliant"
EXPECT_REGEX = "^Check status: Compliant"


def extract_description(text: str, fallback: str) -> str:
    """Primeira entrada do changelog no cabeçalho = descrição original da regra."""
    for line in text.splitlines():
        if not line.startswith("#"):
            # o cabeçalho acabou (ignora o shebang e linhas vazias antes)
            if line.strip() == "" or line.startswith("#!"):
                continue
            break
        m = HEADER_RE.match(line)
        if m:
            return m.group("desc")
    return fallback


def audit_string(s: str) -> str:
    """Escapa para uma string entre aspas duplas no .audit."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_item(path: Path, timeout: int, severity: str | None) -> tuple[str, str, list[str]]:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
    warnings = []

    if "\r" in raw.decode("utf-8", errors="replace"):
        warnings.append("tinha fins de linha Windows (CRLF); convertidos para LF")
    if PASS_MARKER not in text:
        warnings.append(f'não contém "{PASS_MARKER}" — o item vai dar sempre FAILED')

    desc = extract_description(text, fallback=path.stem.replace("_", " "))
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    cmd = f"echo {b64} | base64 -d | bash"

    comment = "\n".join(f"# | {l}" for l in text.rstrip("\n").splitlines())
    lines = [
        f"# Origem: {path.name}",
        comment,
        "    <custom_item>",
        "      type          : CMD_EXEC",
        f'      description   : "{audit_string(desc)}"',
        f'      cmd           : "{cmd}"',
        f'      expect        : "{EXPECT_REGEX}"',
        "      match_case    : YES",
        f'      timeout       : "{timeout}"',
        "      dont_echo_cmd : YES",
    ]
    if severity:
        lines.append(f"      severity      : {severity}")
    lines.append("    </custom_item>")
    return desc, "\n".join(lines), warnings


def wrap(items: list[str]) -> str:
    body = "\n\n".join(items)
    return f'<check_type:"Unix">\n\n{body}\n\n</check_type>\n'


def collect(inputs: list[str]) -> list[Path]:
    files = []
    for i in inputs:
        p = Path(i)
        if p.is_dir():
            files += sorted(p.glob("*.sh"))
        elif p.is_file():
            files.append(p)
        else:
            sys.exit(f"erro: não encontrei {i}")
    if not files:
        sys.exit("erro: nenhum script .sh encontrado")
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", default=[str(BASH_DIR)],
                    help="scripts .sh ou pastas com scripts (default: pasta bash/)")
    ap.add_argument("-o", "--output", required=True,
                    help="nome do .audit a gerar; sem pasta, vai para audits/ (a extensão .audit é opcional)")
    ap.add_argument("--split", action="store_true", help="gerar um .audit por script")
    ap.add_argument("--timeout", type=int, default=300, help="timeout por check em segundos (default 300)")
    ap.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], help="severidade dos items")
    args = ap.parse_args()

    files = collect(args.inputs)
    built, seen, problems = [], {}, 0

    for f in files:
        desc, item, warns = build_item(f, args.timeout, args.severity)
        if desc in seen:
            warns.append(f'descrição duplicada com {seen[desc]} — o Tenable gera o plugin ID a partir dela')
        seen.setdefault(desc, f.name)
        for w in warns:
            print(f"aviso [{f.name}]: {w}", file=sys.stderr)
            problems += 1
        built.append((f, item))

    out = Path(args.output)
    if out.parent == Path("."):          # só um nome -> vai para audits/
        out = AUDITS_DIR / out
    if not args.split and out.suffix != ".audit":
        out = out.with_name(out.name + ".audit")
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.split:
        out.mkdir(parents=True, exist_ok=True)
        for f, item in built:
            (out / f"{f.stem}.audit").write_text(wrap([item]), encoding="utf-8")
        print(f"{len(built)} ficheiros .audit escritos em {out}/")
    else:
        out.write_text(wrap([i for _, i in built]), encoding="utf-8")
        print(f"{len(built)} checks escritos em {out}")
    if problems:
        print(f"{problems} aviso(s) — ver acima", file=sys.stderr)


if __name__ == "__main__":
    main()
