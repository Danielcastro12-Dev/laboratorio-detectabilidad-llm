# Revisión adversarial de Gate B

## Preguntas y respuestas

1. **¿La selección de 25 tareas es reproducible?** Sí. Se fija la revisión del dataset, se normaliza el CWE y se ordena por CWE, subconjunto e identificador. El manifiesto está en `data/manifests/task_selection_v0.1.csv`.
2. **¿La falta de tareas CWE-798 invalida el corpus?** No invalida CodeSecEval; invalida la selección original. Se sustituyó explícitamente por CWE-22, sin incorporar LLMSecEval.
3. **¿Funcionalidad equivale a seguridad?** No. Los estados de funcionalidad y los resultados de seguridad se almacenan por separado.
4. **¿Un detector puede definir la verdad de su propia evaluación?** No. La mayoría de detectores y el resultado individual del detector están excluidos como verdad primaria.
5. **¿Un fallo de infraestructura puede contarse como ausencia de hallazgo?** No. Los fallos de ejecución y de herramientas tienen estados separados.
6. **¿Qué ocurre si el sandbox no está disponible?** Se detiene toda ejecución de código generado. No se sustituye por ejecución directa sobre Windows.
7. **¿Se pueden fijar modelos con nombres comerciales?** No. Solo IDs exactos, proveedor, fecha de consulta y parámetros completos.
8. **¿Se puede distribuir el dataset sin verificar la licencia?** No. El README indica que la licencia está bajo revisión; se debe limitar la distribución y conservar la procedencia.

## Resultado

El diseño es coherente para continuar con configuración y pruebas unitarias, pero el piloto está bloqueado hasta habilitar el sandbox y congelar los modelos.
