# Gate A — verificación de CodeSecEval

**Estado:** DATASET VERIFICADO; INFRAESTRUCTURA PENDIENTE
**Fecha de auditoría:** 2026-09-21

## Fuente congelada

- Dataset: `JasonWang1/CodeSecEval`
- Revisión Hugging Face: `c3ffce09269f2d7b092888efe05d070b6fcb97f5`
- Repositorio oficial asociado: `CY-SCUT-MS/CodeSecEval`
- Archivos descargados:
  - `data/raw/CodeSecEval/data/SecEvalBase/test.jsonl`
  - `data/raw/CodeSecEval/data/SecEvalPlus/test.jsonl`
  - `data/raw/CodeSecEval/README.md`
- Hashes: `data/manifests/codesec_eval_sha256.txt`

## Resultados reproducibles

- Registros totales: **255**.
- Tareas con identificador único: **255**.
- Categorías CWE observadas: **71** después de normalizar ceros iniciales.
- Cada registro contiene los ocho campos esperados:
  `ID`, `Problem`, `Insecure Code`, `Secure Code`, `Test`, `Test-FP`, `Test-SP` y `Entry_Point`.
- Distribución por subconjunto: `SecEvalBase=115`, `SecEvalPlus=140`.
- Inventario completo: `data/manifests/codesec_eval_inventory.csv`.
- Resumen CWE: `data/manifests/cwe_summary.csv`.
- Selección reproducible de 25 tareas: `data/manifests/task_selection_v0.1.csv`.
- Las 25 tareas seleccionadas pasan `ast.parse` en código inseguro, código seguro y las tres suites de pruebas; no se ejecutó código del dataset.

## Comprobación de las CWE previstas

| CWE | Tareas | Estado |
|---|---:|---|
| CWE-78 | 12 | suficiente para seleccionar 5 |
| CWE-79 | 12 | suficiente para seleccionar 5 |
| CWE-89 | 12 | suficiente para seleccionar 5 |
| CWE-502 | 14 | suficiente para seleccionar 5 |
| CWE-798 | 2 | insuficiente para seleccionar 5 |

## Decisión aplicada

Se sustituye CWE-798 por **CWE-22**, manteniendo cinco tareas por CWE y CodeSecEval como corpus único. La matriz congelada queda: CWE-22, CWE-78, CWE-79, CWE-89 y CWE-502.

La selección de tareas concretas debe hacerse mediante un manifiesto reproducible, verificando además que CWE-79 conserve tareas Python ejecutables y pruebas válidas.

## Licencia

El README del dataset indica que la licencia está bajo revisión. El repositorio GitHub asociado declara MIT, pero eso no prueba por sí solo la licencia de los archivos del dataset. La licencia debe documentarse como una limitación de procedencia antes de distribuir artefactos derivados.

## Infraestructura

Docker Desktop está instalado (versión 4.91.0), pero no inicia porque WSL no está habilitado en Windows. La ejecución aislada del código generado no puede comenzar hasta habilitar WSL y verificar `docker info` con el daemon activo.

## Alcance confirmado

- CodeSecEval es el corpus principal y único.
- LLMSecEval queda excluido del laboratorio.
- El estado del arte queda fuera de este plan operativo porque ya forma parte del anteproyecto.
- La redacción de la tesis, la presentación y la sustentación quedan fuera del plan técnico y serán realizadas por Daniel.
