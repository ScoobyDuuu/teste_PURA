"""Verificação mínima offline (aproxima ruff E/F): imports não usados, lambda atribuído,
nomes ambíguos (l, O, I), variáveis locais não usadas e linhas > 120 colunas.
O CI usa o ruff de verdade; este script serve para checar sem rede."""
import ast
import pathlib
import sys

MAXLEN = 120


def check(path: pathlib.Path):
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    out = []
    for i, line in enumerate(src.splitlines(), 1):
        if len(line) > MAXLEN:
            out.append((i, f"E501 linha com {len(line)} colunas"))
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for a in node.names:
                imported[a.asname or a.name] = node.lineno
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    strs = " ".join(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    exported = path.name == "__init__.py"
    for name, ln in imported.items():
        if name not in names and name not in attrs and name not in strs and not exported:
            out.append((ln, f"F401 import não usado: {name}"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda) and \
                all(isinstance(t, ast.Name) for t in node.targets):
            out.append((node.lineno, "E731 lambda atribuído a variável"))
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in ("l", "O", "I"):
            out.append((node.lineno, f"E741 nome ambíguo: {node.id}"))
        if isinstance(node, ast.arg) and node.arg in ("l", "O", "I"):
            out.append((node.lineno, f"E741 argumento ambíguo: {node.arg}"))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stores, loads = {}, set()
            for n in ast.walk(node):
                if isinstance(n, ast.Name):
                    if isinstance(n.ctx, ast.Store):
                        stores.setdefault(n.id, n.lineno)
                    else:
                        loads.add(n.id)
            for n in ast.walk(node):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    v = n.targets[0].id
                    if v not in loads and not v.startswith("_"):
                        out.append((n.lineno, f"F841 variável local não usada: {v}"))
    return out


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    bad = 0
    for p in sorted(root.rglob("*.py")):
        if ".venv" in p.parts:
            continue
        for ln, msg in sorted(set(check(p))):
            print(f"{p}:{ln}: {msg}")
            bad += 1
    print("OK" if not bad else f"{bad} problema(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
