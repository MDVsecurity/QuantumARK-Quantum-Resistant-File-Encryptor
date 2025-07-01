#!/bin/bash
# Auditorías de Formato y Estilo para QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
REPORTS_DIR="$PROJECT_ROOT/audits/reports/formatting"

echo "🎨 Ejecutando auditorías de formato y estilo..."
mkdir -p "$REPORTS_DIR"
cd "$PROJECT_ROOT"

# Flake8 - Estilo PEP 8
echo "📏 Ejecutando Flake8..."
flake8 . --config=audits/.flake8 --format=json > "$REPORTS_DIR/flake8_report.json" 2>&1

# Black - Verificación de formato
echo "⚫ Ejecutando Black Check..."
black . --check --diff > "$REPORTS_DIR/black_report.txt" 2>&1

# isort - Verificación de imports
echo "📦 Ejecutando isort Check..."
isort . --check-only --diff > "$REPORTS_DIR/isort_report.txt" 2>&1

# Generar reporte de estadísticas de formato
echo "📊 Generando estadísticas de formato..."
cat > "$REPORTS_DIR/format_stats.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tools_executed": ["flake8", "black", "isort"],
  "files_analyzed": $(find . -name "*.py" -not -path "./audits/*" -not -path "./audit_env/*" | wc -l),
  "project": "QuantumARK"
}
EOF

echo "✅ Auditorías de formato completadas!"
