# Gate B — diseño experimental

**Estado:** PENDIENTE DE APROBACIÓN TÉCNICA

## Decisiones congeladas

- Corpus único: CodeSecEval, revisión Hugging Face `c3ffce09269f2d7b092888efe05d070b6fcb97f5`.
- Tareas: 25, cinco por CWE.
- CWE: CWE-22, CWE-78, CWE-79, CWE-89 y CWE-502.
- Repeticiones: 5 por modelo y tarea.
- Outputs objetivo: 375.
- Funcionalidad: estados explícitos; no se usa un umbral global arbitrario.
- Ground truth: evidencia de dataset, pruebas funcionales, pruebas dinámicas y adjudicación manual ciega; no mayoría de detectores.
- Estado `inconclusive`: permitido y reportado.
- Sandbox: Docker, sin red, raíz de solo lectura, usuario no root, `no_new_privileges`, 256 MB, 1 CPU, 5 s y 32 procesos.
- LLMSecEval: excluido.

## Respuestas de control

- **¿Qué ocurre si no existen cinco tareas para una CWE?** Se detiene la congelación y se registra una sustitución explícita con otra CWE de CodeSecEval; no se mezcla otro dataset ni se inventan tareas.
- **¿Qué ocurre si una tarea necesita red?** Se clasifica como incompatible con el sandbox principal, se conserva como `inconclusive` o se excluye con justificación; no se habilita red globalmente.
- **¿Qué ocurre si el output no contiene código?** Se registra como `non_functional` o `inconclusive` según la evidencia disponible y no se ejecuta.
- **¿Qué ocurre si CodeQL no puede crear una base?** Se registra un resultado `tool_unavailable` separado de un no hallazgo; no se convierte en falso negativo.
- **¿Qué ocurre si la revisión manual produce `inconclusive`?** Se conserva ese estado, se excluye del denominador de métricas que exijan verdad binaria y se reporta su proporción.
- **¿Qué ocurre si faltan outputs?** El manifiesto de completitud falla; no se presenta el corpus como 375 hasta resolver o documentar la pérdida.
- **¿Qué ocurre si el auditor LLM cambia de formato?** Se conserva la respuesta cruda y falla la normalización hasta adaptar un parser versionado; no se descarta silenciosamente.

## Bloqueos resueltos

1. Docker Desktop verificado: `docker info` responde y `docker run hello-world` ejecuta correctamente.
2. Modelos congelados en `configs/models_v0.1.yaml`:
   - `deepseek/deepseek-v3.2` (general común)
   - `anthropic/claude-opus-4.5` (general alto rendimiento)
   - `qwen/qwen3-coder-next` (especializado en código)
3. Modelo auditor: `anthropic/claude-opus-4.5`.

## Bloqueo restante

La licencia del dataset declara estar bajo revisión; se conserva como limitación de procedencia.

## Resultado

Gate B aprobado para continuar con la construcción del sandbox y la generación del piloto.

