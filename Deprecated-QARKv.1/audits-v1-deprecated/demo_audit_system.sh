#!/bin/bash
# Script de demostración del sistema completo de auditoría QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
AUDIT_DIR="$PROJECT_ROOT/audits"
REPORTS_DIR="$AUDIT_DIR/reports"

clear
echo "🔍===============================================🔍"
echo "  DEMOSTRACIÓN DEL SISTEMA DE AUDITORÍA"
echo "           QuantumARK Security Suite"
echo "🔍===============================================🔍"
echo ""

# Mostrar información del proyecto
echo "📊 INFORMACIÓN DEL PROYECTO"
echo "----------------------------"
echo "📁 Proyecto: QuantumARK"
echo "📍 Ubicación: $PROJECT_ROOT"
echo "🕒 Fecha: $(date)"
echo "🔧 Python: $(python3 --version)"
echo "📄 Archivos Python: $(find . -name "*.py" -not -path "./audits/*" -not -path "./audit_env/*" | wc -l)"
echo ""

# Activar entorno
echo "🔄 Activando entorno de auditoría..."
source "$PROJECT_ROOT/activate_audit_env.sh"
echo ""

# Limpiar reportes anteriores
echo "🧹 Limpiando reportes anteriores..."
rm -rf "$REPORTS_DIR"
mkdir -p "$REPORTS_DIR"/{security,quality,formatting,testing}
echo ""

# Ejecutar auditorías por categoría
echo "🚀 INICIANDO AUDITORÍAS COMPLETAS"
echo "================================="
echo ""

# 1. Auditorías de Seguridad
echo "🔒 [1/4] AUDITORÍAS DE SEGURIDAD"
echo "--------------------------------"
"$AUDIT_DIR/run_security_audit.sh"
echo ""

# 2. Auditorías de Calidad
echo "🔍 [2/4] AUDITORÍAS DE CALIDAD"
echo "------------------------------"
"$AUDIT_DIR/run_quality_audit.sh"
echo ""

# 3. Auditorías de Formato
echo "🎨 [3/4] AUDITORÍAS DE FORMATO"
echo "------------------------------"
"$AUDIT_DIR/run_format_audit.sh"
echo ""

# 4. Auditorías de Testing
echo "🧪 [4/4] AUDITORÍAS DE TESTING"
echo "------------------------------"
"$AUDIT_DIR/run_testing_audit.sh"
echo ""

# Generar reporte consolidado
echo "📊 GENERANDO REPORTE CONSOLIDADO"
echo "================================"
python3 "$AUDIT_DIR/generate_consolidated_report.py"
echo ""

# Mostrar resumen de resultados
echo "📈 RESUMEN DE RESULTADOS"
echo "========================"

# Contar archivos generados
security_files=$(find "$REPORTS_DIR/security" -type f 2>/dev/null | wc -l)
quality_files=$(find "$REPORTS_DIR/quality" -type f 2>/dev/null | wc -l)
format_files=$(find "$REPORTS_DIR/formatting" -type f 2>/dev/null | wc -l)
testing_files=$(find "$REPORTS_DIR/testing" -type f 2>/dev/null | wc -l)
total_files=$(find "$REPORTS_DIR" -type f 2>/dev/null | wc -l)

echo "🔒 Reportes de Seguridad: $security_files archivos"
echo "🔍 Reportes de Calidad: $quality_files archivos"
echo "🎨 Reportes de Formato: $format_files archivos"
echo "🧪 Reportes de Testing: $testing_files archivos"
echo "📊 Total de Reportes: $total_files archivos"
echo ""

# Mostrar ubicaciones importantes
echo "📁 UBICACIONES DE REPORTES"
echo "==========================="
echo "📂 Todos los reportes: $REPORTS_DIR/"
echo "🌐 Reporte consolidado: $REPORTS_DIR/consolidated_report.html"
echo "📄 Resumen JSON: $REPORTS_DIR/audit_summary.json"
echo ""

# Comandos útiles
echo "💡 COMANDOS ÚTILES"
echo "=================="
echo "🌐 Ver reporte HTML: open $REPORTS_DIR/consolidated_report.html"
echo "📊 Explorar reportes: ls -la $REPORTS_DIR/"
echo "🔄 Re-ejecutar auditoría: $AUDIT_DIR/run_full_audit.sh"
echo ""

# Verificar integridad del sistema
echo "✅ VERIFICACIÓN DEL SISTEMA"
echo "==========================="

# Verificar herramientas
tools_working=0
total_tools=17

for tool in bandit semgrep safety pip-audit mypy pyright pylint flake8 black isort prospector radon lizard checkov pytest coverage pre-commit; do
    if command -v "$tool" &> /dev/null; then
        ((tools_working++))
    fi
done

echo "🔧 Herramientas funcionando: $tools_working/$total_tools"

# Verificar archivos críticos
critical_files=(
    "$AUDIT_DIR/run_full_audit.sh"
    "$AUDIT_DIR/generate_consolidated_report.py"
    "$AUDIT_DIR/requirements.txt"
    "$PROJECT_ROOT/.pre-commit-config.yaml"
)

files_ok=0
for file in "${critical_files[@]}"; do
    if [[ -f "$file" ]]; then
        ((files_ok++))
    fi
done

echo "📄 Archivos críticos: $files_ok/${#critical_files[@]}"

# Status final
if [[ $tools_working -eq $total_tools ]] && [[ $files_ok -eq ${#critical_files[@]} ]]; then
    echo "🎉 ¡SISTEMA COMPLETAMENTE FUNCIONAL!"
else
    echo "⚠️  Sistema funcional con algunas limitaciones"
fi

echo ""
echo "🔍===============================================🔍"
echo "        ¡DEMOSTRACIÓN COMPLETADA!"
echo "🔍===============================================🔍"
