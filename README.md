# Laboratorio de Detectabilidad LLM

Laboratorio reproducible para evaluar la **seguridad** y la **detectabilidad** del código Python generado por modelos de lenguaje. Repositorio de evidencia del trabajo de grado *Seguridad y detectabilidad del código generado por modelos de lenguaje* (Ingeniería de Sistemas, Universidad de Pamplona).

## El experimento

- **Corpus:** 375 outputs Python = 3 modelos × 25 tareas de CodeSecEval × 5 repeticiones, estratificados en cinco categorías CWE (CWE-22, CWE-78, CWE-79, CWE-89, CWE-502). Corpus único: CodeSecEval (revisión congelada `c3ffce09`).
- **Modelos generadores:** `deepseek/deepseek-v3.2`, `anthropic/claude-opus-4.5`, `qwen/qwen3-coder-next` (vía OpenRouter; temperatura 0.2, top_p 0.95).
- **Auditor LLM:** `nvidia/nemotron-3-ultra-550b-a55b`.
- **Detectores evaluados:** Semgrep 1.141.0, Bandit 1.9.4, CodeQL CLI 2.27.2 y auditor LLM.
- **Gold truth:** adjudicación asistida por LLM con la identidad del modelo oculta, validada por el investigador (291 confirmados seguros / 84 confirmados vulnerables).
- **Resultados principales:** auditor LLM F1 0.750 (P 0.900 / R 0.643), Bandit F1 0.308, Semgrep F1 0.158, CodeQL 0 hallazgos en este entorno. Las vulnerabilidades no detectadas sobre su CWE objetivo se concentran en configuraciones de librerías (Jinja2 sin autoescape, `tarfile` sin `filter="data"`).

## Estructura

| Ruta | Contenido |
|---|---|
| `src/llm_lab/` | Biblioteca: esquemas, generación, ejecución en sandbox, detección |
| `tools/` | Scripts CLI de cada etapa (corpus, pruebas, detectores, análisis) |
| `configs/` | Configuración de experimento, modelos y esquemas (YAML/JSON) |
| `data/raw/corpus_v0.1/` | 375 outputs con prompt, respuesta, metadatos y hash SHA-256 |
| `data/raw/CodeSecEval/` | Instantánea congelada del dataset |
| `data/manifests/` | Manifiesto del corpus, selección de tareas e inventarios |
| `data/derived/` | Resultados de detectores, matriz modelo×CWE×detector, catálogos |
| `data/adjudicated/` | Gold truth v0.6 y colas de revisión |
| `sandbox/` | Dockerfile y dependencias del sandbox endurecido |

## Reproducción

```bash
uv sync                                                    # dependencias
uv run pytest                                              # 27 pruebas (requiere Docker Desktop)
uv run python tools/generate_full_corpus.py --tasks data/manifests/task_selection_v0.1.csv \
    --models configs/models_v0.1.yaml --output-dir data/raw/corpus_v0.1/
uv run python tools/run_full_functional_tests.py           # pruebas funcionales en sandbox
uv run python tools/run_detectors.py --output-dir data/raw/corpus_v0.1/ \
    --output data/derived/detector_results.json
uv run python tools/run_codeql_detector.py                 # CodeQL (ver limitación abajo)
uv run python tools/analyze_results.py                     # matrices y métricas
uv run python tools/check_completeness.py                  # verificación del corpus
```

La generación de corpus es **resumible**: escribe un manifiesto incremental y reanuda donde se interrumpió. La deduplicación es por clave lógica `(task_id, model_id, repetition)`, no por `output_id`.

## Notas y limitaciones

- **CodeQL reportó 0 hallazgos** en el entorno de desarrollo (Windows), incluso con ejemplos mínimos reproducibles; se documenta como limitación metodológica y se excluye de las comparaciones cualitativas.
- Las pruebas de integración ejecutan código en un **sandbox Docker** (`llm-lab-sandbox:v0.2`, sin red, usuario sin privilegios, sistema de archivos de solo lectura); Docker Desktop debe estar corriendo.
- La clave de OpenRouter vive en `.env`, que **nunca se versiona**.
- Los archivos generados en `data/derived/` no se editan a mano: se regeneran con los scripts de `tools/`.

## Herramientas

Python 3.12.7 · uv 0.12.17 · Docker Desktop 29.8.0 · Semgrep 1.141.0 · Bandit 1.9.4 · CodeQL CLI 2.27.2
