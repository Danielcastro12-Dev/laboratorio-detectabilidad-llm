"""Verifica que el reencuadre de adjudicación asistida por LLM quedó en el docx final."""
from pathlib import Path

from docx import Document

p = Path("reports/technical/Informe_Final_Daniel_Castro.docx")
doc = Document(str(p))

frases = [
    "adjudicación asistida por LLM con identidad del modelo",
    "se examinaron caso por caso a nivel de código",
    "examinó el código caso por caso",
    "validación del investigador",
    "LLM-assisted adjudication",
    "investigator validation",
    "segundo revisor independiente",
]
todo = "\n".join(par.text for par in doc.paragraphs)
for f in frases:
    n = todo.count(f)
    print(f"{'OK  ' if n else 'FALTA'} ({n})  {f}")

print()
for viejo in [
    "manual blind review",
    "revisión ciega manual",
    "revisión manual con identidad",
    "revisaron manualmente",
    "revisó manualmente",
    "manually reviewed case by case",
    "REVISIÓN MANUAL DEL DESACUERDO",
]:
    n = todo.count(viejo)
    print(f"{'OK  ausente   ' if n == 0 else 'PRESENTE!!'} ({n})  {viejo}")
