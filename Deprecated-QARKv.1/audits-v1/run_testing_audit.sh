#!/bin/bash
# Auditorías de Testing para QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
REPORTS_DIR="$PROJECT_ROOT/audits/reports/testing"

echo "🧪 Ejecutando auditorías de testing..."
mkdir -p "$REPORTS_DIR"
cd "$PROJECT_ROOT"

# Pytest y Coverage
echo "🔬 Ejecutando Pytest con Coverage..."
pytest --config-file=audits/pytest.ini > "$REPORTS_DIR/pytest_report.txt" 2>&1

# Coverage standalone report
echo "📊 Generando reporte de Coverage..."
coverage report > "$REPORTS_DIR/coverage_summary.txt" 2>&1
coverage json -o "$REPORTS_DIR/coverage.json" 2>&1

# Generar estadísticas de testing
echo "📈 Generando estadísticas de testing..."
total_tests=$(grep -E "collected|passed|failed|skipped" "$REPORTS_DIR/pytest_report.txt" | head -1 | grep -o '[0-9]\+' | head -1 || echo "0")
coverage_percent=$(coverage report | tail -1 | grep -o '[0-9]\+%' | head -1 || echo "0%")

cat > "$REPORTS_DIR/testing_stats.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_tests": ${total_tests:-0},
  "coverage_percentage": "$coverage_percent",
  "tools_executed": ["pytest", "coverage"],
  "project": "QuantumARK"
}
EOF

echo "✅ Auditorías de testing completadas!"
