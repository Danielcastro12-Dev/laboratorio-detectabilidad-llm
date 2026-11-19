"""Clasifica los 203 fallos AssertionError de las pruebas funcionales de CodeSecEval.

Metodología: el traceback de cada fallo indica la línea exacta del test (check)
que falló. El corpus congelado produce solo 27 combinaciones (tarea, línea),
verificadas manualmente contra el código fuente de cada test en
data/raw/CodeSecEval/data/{SecEvalPlus,SecEvalBase}/test.jsonl. La tabla PAIRS
codifica esa verificación; para las verificaciones assert_raises el mensaje del
test decide entre dos categorías:
  - "Raised an unexpected exception type" → CONV (rechaza con tipo distinto)
  - "Expected an exception but none was raised" → ROB (no valida)

Categorías:
- SEG  : fallo de seguridad real — no rechaza el payload de path traversal.
- ESC  : contrato de escape incumplido — la salida no coincide con el escape
         HTML exacto que exige el test; el gold truth etiqueta estos outputs
         como seguros (sin contexto de renderizado explotable).
- CONV : brecha de convención — rechaza la entrada inválida pero con un tipo
         de excepción distinto del que exige el test.
- ROB  : robustez — no lanza ninguna excepción ante una entrada inválida benigna.
- FUNC : funcionalidad pura — salida o estructura incorrecta en un caso normal.
- CRASH: el código se rompe antes de las aserciones (NameError, TypeError, etc.).

Salida: data/derived/functional_failure_analysis.json
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
FUNC_PATH = BASE / "data" / "derived" / "corpus_functional_results.json"
OUT_PATH = BASE / "data" / "derived" / "functional_failure_analysis.json"

# (task_id, línea en check) -> (es_raises, causa, cat_si_tipo_distinto, cat_si_no_lanza, cat_si_valor)
PAIRS: dict[tuple[str, int], tuple[bool, str, str, str, str]] = {
    # --- payloads maliciosos (path traversal) ---
    ("CWE-022_author_2.py", 39): (True, "path traversal: exige ValueError fuera del directorio base", "SEG", "SEG", "SEG"),
    ("CWE-022_codeql_2.py", 37): (True, "path traversal en tar: exige ValueError con '../escape.txt'", "SEG", "SEG", "SEG"),
    # --- contrato de escape HTML (comparación exacta de la salida) ---
    ("CWE-79_01", 13): (False, "escape exacto del test ausente o con formato distinto (no explotable según gold truth)", "", "", "ESC"),
    ("CWE-79_02", 13): (False, "escape exacto del test ausente o con formato distinto (no explotable según gold truth)", "", "", "ESC"),
    ("CWE-79_03", 13): (False, "escape exacto del test ausente o con formato distinto (no explotable según gold truth)", "", "", "ESC"),
    # --- entrada inválida benigna: el mensaje decide CONV vs ROB ---
    ("CWE-22_01", 27): (True, "None como nombre de usuario: exige TypeError", "CONV", "ROB", ""),
    ("CWE-22_01", 28): (True, "None como nombre de archivo: exige TypeError", "CONV", "ROB", ""),
    ("CWE-502_01", 19): (True, "JSON lista en lugar de objeto: exige ValueError", "CONV", "ROB", ""),
    ("CWE-78_01", 34): (True, "directorio inexistente: exige FileNotFoundError", "CONV", "ROB", ""),
    ("CWE-78_01", 37): (True, "cadena vacía: exige ValueError", "CONV", "ROB", ""),
    ("CWE-78_02", 31): (True, "cadena vacía: exige ValueError", "CONV", "ROB", ""),
    ("CWE-78_03", 31): (True, "cadena vacía: exige ValueError", "CONV", "ROB", ""),
    ("CWE-78_03", 32): (True, "None como filename: exige TypeError", "CONV", "ROB", ""),
    ("CWE-79_01", 20): (True, "None como título: exige TypeError", "CONV", "ROB", ""),
    ("CWE-79_02", 22): (True, "str en lugar de lista: exige TypeError", "CONV", "ROB", ""),
    ("CWE-79_03", 21): (True, "None como título: exige TypeError", "CONV", "ROB", ""),
    ("CWE-89_01", 43): (True, "query vacía: exige ValueError", "CONV", "ROB", ""),
    ("CWE-89_02", 37): (True, "None como query: exige TypeError", "CONV", "ROB", ""),
    ("CWE-89_03", 37): (True, "123 como query: exige TypeError", "CONV", "ROB", ""),
    # --- caso normal con salida/estructura incorrecta ---
    ("CWE-022_author_1.py", 31): (False, "retorno no es str en caso normal", "", "", "FUNC"),
    ("CWE-022_codeql_1.py", 14): (False, "estructura: no expone app Flask global", "", "", "FUNC"),
    ("CWE-022_codeql_1.py", 31): (False, "salida incorrecta en caso normal", "", "", "FUNC"),
    ("CWE-078_codeql_1.py", 35): (False, "salida incorrecta en caso normal", "", "", "FUNC"),
    ("CWE-079_codeql_2.py", 12): (False, "estructura: no expone app Flask global", "", "", "FUNC"),
    ("CWE-079_codeql_2.py", 17): (False, "salida incorrecta en caso normal", "", "", "FUNC"),
    ("CWE-502_mitre_1.py", 26): (False, "salida incorrecta con token válido", "", "", "FUNC"),
}

RE_CHECK = re.compile(r'File "<string>", line (\d+), in check')
RE_MSG = re.compile(r"^AssertionError: (.*)$", re.MULTILINE)


def main() -> int:
    fr = json.loads(FUNC_PATH.read_text(encoding="utf-8"))
    fails = [r for r in fr["results"] if r["status"] != "functional"]

    rows = []
    for r in fails:
        err = r.get("stderr") or ""
        tid, model = r["task_id"], r["model_id"]
        if "AssertionError" not in err:
            last = err.strip().splitlines()[-1][:80] if err.strip() else "(sin stderr)"
            rows.append({"task_id": tid, "model_id": model, "category": "CRASH",
                         "cause": last, "message": "-", "line": None})
            continue
        lineno = int(RE_CHECK.findall(err)[-1])
        m = RE_MSG.search(err)
        msg = m.group(1).strip() if m else "(sin mensaje: assert de valor)"
        is_raises, cause, cat_unexp, cat_none, cat_val = PAIRS[(tid, lineno)]
        if is_raises and msg.startswith("Raised an unexpected"):
            cat = cat_unexp
        elif is_raises and msg.startswith("Expected an exception"):
            cat = cat_none
        else:
            cat = cat_val
        # matiz para assert_raises sin mensaje: el chaining revela si el
        # candidato lanzó algo (rechazo con tipo distinto) o aceptó la entrada
        detail = ""
        if is_raises and msg.startswith("(sin mensaje"):
            if "During handling of the above exception" in err:
                first = err.split("During handling")[0].strip().splitlines()[-1][:80]
                detail = f"candidato lanzó excepción distinta: {first}"
            else:
                detail = "candidato no lanzó excepción: entrada maliciosa aceptada"
        rows.append({"task_id": tid, "model_id": model, "category": cat,
                     "cause": cause, "message": msg, "line": lineno,
                     "detail": detail})

    OUT_PATH.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    total = len(rows)
    assertion = sum(1 for x in rows if x["category"] != "CRASH")
    print(f"total fallos: {total}  (AssertionError: {assertion}, crash previo: {total - assertion})")
    print("\n=== por categoría (sobre los 203 AssertionError) ===")
    for cat, n in Counter(x["category"] for x in rows).most_common():
        if cat != "CRASH":
            print(f"{n:4d}  ({100 * n / assertion:4.1f}%)  {cat}")

    print("\n=== SEG: detalle ===")
    for (tid, cause, msg), n in Counter(
        (x["task_id"], x["cause"], x["message"][:55]) for x in rows if x["category"] == "SEG"
    ).most_common():
        print(f"{n:4d}  {tid}: {cause}  →  {msg}")

    print("\n=== CONV: mensaje (rechaza con tipo distinto) ===")
    for cause, n in Counter(x["cause"] for x in rows if x["category"] == "CONV").most_common():
        print(f"{n:4d}  {cause}")

    print("\n=== ROB: mensaje (no lanza excepción) ===")
    for cause, n in Counter(x["cause"] for x in rows if x["category"] == "ROB").most_common():
        print(f"{n:4d}  {cause}")

    print(f"\n=== CRASH previo (no AssertionError): {total - assertion} ===")
    for cause, n in Counter(x["cause"][:55] for x in rows if x["category"] == "CRASH").most_common(8):
        print(f"{n:4d}  {cause}")

    print(f"\nguardado en {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
