#!/bin/bash
# Script completo de auditoría para QuantumARK
# Ejecuta todas las herramientas de análisis de código

set -e  # Salir si algún comando falla

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
AUDIT_DIR="$PROJECT_ROOT/audits"
REPORTS_DIR="$AUDIT_DIR/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "🚀 Iniciando auditoría completa de QuantumARK - $TIMESTAMP"
echo "============================================================"

# Crear directorios de reportes
mkdir -p "$REPORTS_DIR"/{security,quality,formatting,testing}

# Función para verificar si una herramienta está instalada
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "⚠️  $1 no está instalado. Instalando..."
        pip install "$1"
    fi
}

# Función para ejecutar comando y capturar resultado
run_audit() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"

    echo "🔍 Ejecutando $tool_name..."
    if eval "$command" > "$output_file" 2>&1; then
        echo "✅ $tool_name completado"
    else
        echo "❌ $tool_name falló (esto es normal para algunas herramientas)"
    fi
    echo ""
}

cd "$PROJECT_ROOT"

echo "📦 Verificando e instalando herramientas necesarias..."
tools=(bandit semgrep safety pip-audit mypy pyright pylint flake8 black isort prospector radon lizard checkov pytest coverage pre-commit)
for tool in "${tools[@]}"; do
    check_tool "$tool"
done

echo ""
echo "🔒 === AUDITORÍAS DE SEGURIDAD ==="

# Bandit - Análisis de vulnerabilidades
run_audit "Bandit" \
    "bandit -r . -f json -x audits,venv,.venv,.git" \
    "$REPORTS_DIR/security/bandit_report.json"

run_audit "Bandit HTML" \
    "bandit -r . -f html -x audits,venv,.venv,.git" \
    "$REPORTS_DIR/security/bandit_report.html"

# Semgrep - Análisis estático de seguridad
run_audit "Semgrep" \
    "semgrep --config=auto . --json" \
    "$REPORTS_DIR/security/semgrep_report.json"

# Safety - Verificación de dependencias vulnerables
run_audit "Safety" \
    "safety check --json" \
    "$REPORTS_DIR/security/safety_report.json"

# pip-audit - Auditoría de vulnerabilidades
run_audit "pip-audit" \
    "pip-audit --format=json" \
    "$REPORTS_DIR/security/pip_audit_report.json"

# Checkov - Infraestructura como código
run_audit "Checkov" \
    "checkov -d . --framework python --output json" \
    "$REPORTS_DIR/security/checkov_report.json"

echo ""
echo "🔍 === AUDITORÍAS DE CALIDAD ==="

# MyPy - Verificación de tipos
run_audit "MyPy" \
    "mypy . --config-file audits/mypy.ini --json-report $REPORTS_DIR/quality/mypy_json" \
    "$REPORTS_DIR/quality/mypy_report.txt"

# Pyright - Análisis de tipos
run_audit "Pyright" \
    "pyright . --outputjson" \
    "$REPORTS_DIR/quality/pyright_report.json"

# Pylint - Análisis de calidad
run_audit "Pylint" \
    "pylint *.py --rcfile=audits/.pylintrc" \
    "$REPORTS_DIR/quality/pylint_report.json"

# Prospector - Análisis integral
run_audit "Prospector" \
    "prospector . --output-format json" \
    "$REPORTS_DIR/quality/prospector_report.json"

# Radon - Métricas de complejidad
run_audit "Radon CC" \
    "radon cc . --json" \
    "$REPORTS_DIR/quality/radon_cc_report.json"

run_audit "Radon MI" \
    "radon mi . --json" \
    "$REPORTS_DIR/quality/radon_mi_report.json"

# Lizard - Análisis de complejidad
run_audit "Lizard" \
    "lizard . -o $REPORTS_DIR/quality/lizard_report.html" \
    "$REPORTS_DIR/quality/lizard_report.txt"

echo ""
echo "🎨 === AUDITORÍAS DE FORMATO ==="

# Flake8 - Estilo PEP 8
run_audit "Flake8" \
    "flake8 . --config=audits/.flake8 --format=json" \
    "$REPORTS_DIR/formatting/flake8_report.json"

# Black - Verificación de formato
run_audit "Black Check" \
    "black . --check --diff" \
    "$REPORTS_DIR/formatting/black_report.txt"

# isort - Verificación de imports
run_audit "isort Check" \
    "isort . --check-only --diff" \
    "$REPORTS_DIR/formatting/isort_report.txt"

echo ""
echo "🧪 === AUDITORÍAS DE TESTING ==="

# Pytest y Coverage
run_audit "Pytest with Coverage" \
    "pytest --config-file=audits/pytest.ini" \
    "$REPORTS_DIR/testing/pytest_report.txt"

echo ""
echo "📊 === GENERANDO REPORTE CONSOLIDADO ==="

# Generar reporte consolidado
python3 "$AUDIT_DIR/generate_consolidated_report.py"

echo ""
echo "✅ Auditoría completa finalizada!"
echo "📁 Reportes disponibles en: $REPORTS_DIR"
echo "🌐 Reporte consolidado: $REPORTS_DIR/consolidated_report.html"
echo "============================================================"
