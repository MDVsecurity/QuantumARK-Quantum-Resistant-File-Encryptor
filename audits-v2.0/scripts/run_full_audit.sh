#!/bin/bash
# QuantumARK v2.0 - Auditoría Completa
# Ejecuta todas las auditorías disponibles

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPORTS_DIR="$SCRIPT_DIR/../reports"

echo "🔍 QuantumARK v2.0 - Iniciando Auditoría Completa"
echo "📁 Directorio del proyecto: $PROJECT_ROOT"
echo "📊 Reportes se guardarán en: $REPORTS_DIR"
echo ""

# Crear directorios de reportes si no existen
mkdir -p "$REPORTS_DIR"/{security,quality,tests}

# Cambiar al directorio del proyecto
cd "$PROJECT_ROOT"

echo "🛡️  Ejecutando auditoría de seguridad..."
"$SCRIPT_DIR/run_security_audit.sh"

echo ""
echo "📏 Ejecutando análisis de calidad de código..."
"$SCRIPT_DIR/run_code_quality.sh"

echo ""
echo "🧪 Ejecutando tests..."
"$SCRIPT_DIR/run_tests.sh"

echo ""
echo "✅ Auditoría completa finalizada!"
echo "📊 Revisa los reportes en: $REPORTS_DIR"
