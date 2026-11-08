"""Lista o que ainda falta ANTES de congelar a main (tag v1.0.0). Só lê arquivos; não altera nada.
Uso: python tools/preparar_entrega.py   (sai com código 1 se houver pendência)."""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLACEHOLDERS = [
    (".github/CODEOWNERS", r"@integrante-", "troque @integrante-* pelos usuários reais do GitHub"),
    ("GOVERNANCE.md", r"preencher nomes", "liste os nomes dos integrantes"),
    ("SECURITY.md", r"\(preencher\)", "informe o e-mail/contato do mantenedor"),
]


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    pend = []
    for rel, pattern, hint in PLACEHOLDERS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        if re.search(pattern, text):
            pend.append(f"{rel}: {hint}")
    tracked = git("ls-files")
    if tracked is None:
        pend.append("este diretório ainda não é um repositório Git (git init, commit e push para o GitHub público)")
    else:
        if "secrets.h" in [pathlib.PurePosixPath(p).name for p in tracked.splitlines()]:
            pend.append("secrets.h está versionado: remova do Git e troque o segredo (PURA_SECRET)")
        authors = {a for a in (git("log", "--format=%ae") or "").splitlines() if a}
        if len(authors) < 3:
            pend.append(f"o histórico tem {len(authors)} autor(es); a categoria exige 3 a 5 integrantes contribuindo")
        if not git("tag", "--list", "v1.0.0"):
            pend.append("falta a tag v1.0.0 (criar após o último PR, antes de 09/11)")
    for item in pend:
        print("PENDENTE:", item)
    print("Tudo certo para congelar a main." if not pend else f"{len(pend)} pendência(s).")
    return 1 if pend else 0


if __name__ == "__main__":
    sys.exit(main())
