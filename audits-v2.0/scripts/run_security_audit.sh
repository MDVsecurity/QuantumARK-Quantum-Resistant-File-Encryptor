#!/bin/bash
# QuantumARK v2.0 - Auditoría de Seguridad

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPORTS_DIR="$SCRIPT_DIR/../reports/security"
CONFIG_DIR="$SCRIPT_DIR/../config"

echo "🛡️  QuantumARK v2.0 - Auditoría de Seguridad"
echo ""

# Crear directorio de reportes
mkdir -p "$REPORTS_DIR"

# Cambiar al directorio del proyecto
cd "$PROJECT_ROOT"

echo "🔍 Ejecutando Bandit (vulnerabilidades de seguridad)..."
bandit -c "$CONFIG_DIR/.bandit" -r . -f json -o "$REPORTS_DIR/bandit_report.json" || true
bandit -c "$CONFIG_DIR/.bandit" -r . -f txt -o "$REPORTS_DIR/bandit_report.txt" || true

echo "🔒 Ejecutando Safety (dependencias vulnerables)..."
safety check --json --output "$REPORTS_DIR/safety_report.json" || true
safety check --output "$REPORTS_DIR/safety_report.txt" || true

echo "🔍 Ejecutando pip-audit (auditoría de dependencias)..."
pip-audit --format=json --output="$REPORTS_DIR/pip_audit_report.json" || true
pip-audit --format=plain --output="$REPORTS_DIR/pip_audit_report.txt" || true

echo "🔍 Ejecutando Semgrep (análisis estático avanzado)..."
semgrep --config=auto --json --output="$REPORTS_DIR/semgrep_report.json" . || true
semgrep --config=auto --output="$REPORTS_DIR/semgrep_report.txt" . || true

echo ""
echo "✅ Auditoría de seguridad completada!"
echo "📊 Reportes guardados en: $REPORTS_DIR"
