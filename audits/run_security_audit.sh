#!/bin/bash
# Auditorías de Seguridad para QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
REPORTS_DIR="$PROJECT_ROOT/audits/reports/security"

echo "🔒 Ejecutando auditorías de seguridad..."
mkdir -p "$REPORTS_DIR"
cd "$PROJECT_ROOT"

# Bandit
echo "🛡️ Ejecutando Bandit..."
bandit -r . -f json -x audits,venv,.venv,.git > "$REPORTS_DIR/bandit_report.json" 2>&1
bandit -r . -f html -x audits,venv,.venv,.git > "$REPORTS_DIR/bandit_report.html" 2>&1

# Semgrep
echo "🔍 Ejecutando Semgrep..."
semgrep --config=auto . --json > "$REPORTS_DIR/semgrep_report.json" 2>&1

# Safety
echo "🛡️ Ejecutando Safety..."
safety check --json > "$REPORTS_DIR/safety_report.json" 2>&1

# pip-audit
echo "🔍 Ejecutando pip-audit..."
pip-audit --format=json > "$REPORTS_DIR/pip_audit_report.json" 2>&1

echo "✅ Auditorías de seguridad completadas!"
