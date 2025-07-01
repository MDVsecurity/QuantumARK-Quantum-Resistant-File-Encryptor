#!/bin/bash
# QuantumARK v2.0 - Análisis de Calidad de Código

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPORTS_DIR="$SCRIPT_DIR/../reports/quality"
CONFIG_DIR="$SCRIPT_DIR/../config"

echo "📏 QuantumARK v2.0 - Análisis de Calidad de Código"
echo ""

# Crear directorio de reportes
mkdir -p "$REPORTS_DIR"

# Cambiar al directorio del proyecto
cd "$PROJECT_ROOT"

echo "📋 Ejecutando Flake8 (verificación de estilo y complejidad)..."
flake8 --config="$CONFIG_DIR/.flake8" . --statistics --output-file="$REPORTS_DIR/flake8_report.txt"

# Otros análisis como Pylint, MyPy pueden añadirse aquí


echo ""
echo "✅ Análisis de calidad de código completado!"
echo "📊 Reportes guardados en: $REPORTS_DIR"
