#!/bin/bash
# Auditorías de Calidad de Código para QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
REPORTS_DIR="$PROJECT_ROOT/audits/reports/quality"

echo "🔍 Ejecutando auditorías de calidad de código..."
mkdir -p "$REPORTS_DIR"
cd "$PROJECT_ROOT"

# MyPy - Verificación de tipos
echo "🔬 Ejecutando MyPy..."
mypy . --config-file audits/mypy.ini --json-report "$REPORTS_DIR/mypy_json" > "$REPORTS_DIR/mypy_report.txt" 2>&1

# Pyright - Análisis de tipos
echo "🔍 Ejecutando Pyright..."
pyright . --outputjson > "$REPORTS_DIR/pyright_report.json" 2>&1

# Pylint - Análisis de calidad
echo "📋 Ejecutando Pylint..."
pylint *.py --rcfile=audits/.pylintrc --output-format=json > "$REPORTS_DIR/pylint_report.json" 2>&1

# Prospector - Análisis integral
echo "🔬 Ejecutando Prospector..."
prospector . --output-format json > "$REPORTS_DIR/prospector_report.json" 2>&1

# Radon - Métricas de complejidad
echo "📈 Ejecutando Radon CC..."
radon cc . --json > "$REPORTS_DIR/radon_cc_report.json" 2>&1

echo "📈 Ejecutando Radon MI..."
radon mi . --json > "$REPORTS_DIR/radon_mi_report.json" 2>&1

# Lizard - Análisis de complejidad
echo "🦎 Ejecutando Lizard..."
lizard . -o "$REPORTS_DIR/lizard_report.html" > "$REPORTS_DIR/lizard_report.txt" 2>&1

echo "✅ Auditorías de calidad completadas!"
