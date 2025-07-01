#!/bin/bash
# Utilidades de mantenimiento para el sistema de auditoría QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
AUDIT_DIR="$PROJECT_ROOT/audits"

show_help() {
    echo "🔧 UTILIDADES DE MANTENIMIENTO - Sistema de Auditoría QuantumARK"
    echo "================================================================="
    echo ""
    echo "Uso: $0 [comando]"
    echo ""
    echo "Comandos disponibles:"
    echo ""
    echo "📦 Gestión de Dependencias:"
    echo "  update-tools     Actualizar todas las herramientas de auditoría"
    echo "  check-tools      Verificar que todas las herramientas estén instaladas"
    echo "  install-missing  Instalar herramientas faltantes"
    echo ""
    echo "🧹 Limpieza:"
    echo "  clean-reports    Limpiar todos los reportes generados"
    echo "  clean-cache      Limpiar cache de Python y herramientas"
    echo "  clean-all        Limpieza completa (reportes + cache)"
    echo ""
    echo "⚙️ Configuración:"
    echo "  reset-config     Restaurar configuraciones por defecto"
    echo "  setup-hooks      Configurar pre-commit hooks"
    echo "  update-github    Actualizar workflow de GitHub Actions"
    echo ""
    echo "📊 Reportes:"
    echo "  quick-check      Auditoría rápida (solo esenciales)"
    echo "  full-audit       Auditoría completa con todos los reportes"
    echo "  status           Mostrar estado del sistema"
    echo ""
    echo "❓ Ayuda:"
    echo "  help            Mostrar esta ayuda"
    echo ""
}

update_tools() {
    echo "📦 Actualizando herramientas de auditoría..."
    source "$PROJECT_ROOT/activate_audit_env.sh"
    pip install --upgrade -r "$AUDIT_DIR/requirements.txt"
    echo "✅ Herramientas actualizadas"
}

check_tools() {
    echo "🔍 Verificando herramientas instaladas..."
    source "$PROJECT_ROOT/activate_audit_env.sh"

    tools=(bandit semgrep safety pip-audit mypy pyright pylint flake8 black isort prospector radon lizard checkov pytest coverage pre-commit)
    working=0
    total=${#tools[@]}

    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo "✅ $tool"
            ((working++))
        else
            echo "❌ $tool - NO ENCONTRADO"
        fi
    done

    echo ""
    echo "📊 Resumen: $working/$total herramientas funcionando"

    if [[ $working -eq $total ]]; then
        echo "🎉 ¡Todas las herramientas están funcionando!"
    else
        echo "⚠️  Algunas herramientas necesitan ser instaladas"
        echo "💡 Ejecuta: $0 install-missing"
    fi
}

install_missing() {
    echo "🔧 Instalando herramientas faltantes..."
    source "$PROJECT_ROOT/activate_audit_env.sh"

    tools=(bandit semgrep safety pip-audit mypy pyright pylint flake8 black isort prospector radon lizard checkov pytest coverage pre-commit)

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "📦 Instalando $tool..."
            pip install "$tool"
        fi
    done

    echo "✅ Instalación completada"
}

clean_reports() {
    echo "🧹 Limpiando reportes..."
    rm -rf "$AUDIT_DIR/reports"
    echo "✅ Reportes eliminados"
}

clean_cache() {
    echo "🧹 Limpiando cache..."
    find "$PROJECT_ROOT" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
    find "$PROJECT_ROOT" -name "*.pyc" -delete 2>/dev/null
    find "$PROJECT_ROOT" -name ".mypy_cache" -type d -exec rm -rf {} + 2>/dev/null
    find "$PROJECT_ROOT" -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null
    rm -f "$PROJECT_ROOT/.coverage" 2>/dev/null
    rm -rf "$PROJECT_ROOT/htmlcov" 2>/dev/null
    echo "✅ Cache limpiado"
}

clean_all() {
    clean_reports
    clean_cache
    echo "✅ Limpieza completa finalizada"
}

reset_config() {
    echo "⚙️ Restaurando configuraciones..."

    # Recrear enlaces simbólicos
    ln -sf "$AUDIT_DIR/.flake8" "$PROJECT_ROOT/.flake8"
    ln -sf "$AUDIT_DIR/mypy.ini" "$PROJECT_ROOT/mypy.ini"
    ln -sf "$AUDIT_DIR/.bandit" "$PROJECT_ROOT/.bandit"
    ln -sf "$AUDIT_DIR/pytest.ini" "$PROJECT_ROOT/pytest.ini"
    ln -sf "$AUDIT_DIR/.pre-commit-config.yaml" "$PROJECT_ROOT/.pre-commit-config.yaml"

    echo "✅ Configuraciones restauradas"
}

setup_hooks() {
    echo "🎣 Configurando pre-commit hooks..."
    source "$PROJECT_ROOT/activate_audit_env.sh"

    if [[ -f "$PROJECT_ROOT/.pre-commit-config.yaml" ]]; then
        pre-commit install
        echo "✅ Pre-commit hooks configurados"
    else
        echo "❌ No se encontró .pre-commit-config.yaml"
        echo "💡 Ejecuta: $0 reset-config"
    fi
}

update_github() {
    echo "🐙 Actualizando GitHub Actions..."
    mkdir -p "$PROJECT_ROOT/.github/workflows"
    cp "$AUDIT_DIR/github_workflow.yml" "$PROJECT_ROOT/.github/workflows/audit.yml"
    echo "✅ Workflow de GitHub Actions actualizado"
}

quick_check() {
    echo "⚡ Ejecutando auditoría rápida..."
    source "$PROJECT_ROOT/activate_audit_env.sh"

    mkdir -p "$AUDIT_DIR/reports/quick"

    echo "🔒 Bandit (seguridad)..."
    bandit -r . -f json -x audits,audit_env,.git > "$AUDIT_DIR/reports/quick/bandit.json" 2>&1

    echo "📏 Flake8 (estilo)..."
    flake8 . --config="$AUDIT_DIR/.flake8" > "$AUDIT_DIR/reports/quick/flake8.txt" 2>&1

    echo "🔬 MyPy (tipos)..."
    mypy . --config-file="$AUDIT_DIR/mypy.ini" > "$AUDIT_DIR/reports/quick/mypy.txt" 2>&1

    echo "✅ Auditoría rápida completada - Reportes en: $AUDIT_DIR/reports/quick/"
}

full_audit() {
    echo "🚀 Ejecutando auditoría completa..."
    "$AUDIT_DIR/run_full_audit.sh"
}

show_status() {
    echo "📊 ESTADO DEL SISTEMA DE AUDITORÍA"
    echo "==================================="
    echo ""

    # Información básica
    echo "📁 Proyecto: QuantumARK"
    echo "📍 Ubicación: $PROJECT_ROOT"
    echo "🕒 Fecha: $(date)"
    echo ""

    # Archivos Python
    python_files=$(find "$PROJECT_ROOT" -name "*.py" -not -path "./audits/*" -not -path "./audit_env/*" | wc -l)
    echo "📄 Archivos Python: $python_files"

    # Herramientas
    source "$PROJECT_ROOT/activate_audit_env.sh" 2>/dev/null
    tools=(bandit semgrep safety pip-audit mypy pyright pylint flake8 black isort prospector radon lizard checkov pytest coverage pre-commit)
    working=0
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            ((working++))
        fi
    done
    echo "🔧 Herramientas: $working/${#tools[@]} funcionando"

    # Reportes
    if [[ -d "$AUDIT_DIR/reports" ]]; then
        report_count=$(find "$AUDIT_DIR/reports" -type f 2>/dev/null | wc -l)
        echo "📊 Reportes generados: $report_count"
        echo "📅 Último reporte: $(ls -t "$AUDIT_DIR/reports"/*.html 2>/dev/null | head -1 | xargs stat -f "%Sm" 2>/dev/null || echo "Ninguno")"
    else
        echo "📊 Reportes generados: 0"
    fi

    # Pre-commit
    if [[ -f "$PROJECT_ROOT/.git/hooks/pre-commit" ]]; then
        echo "🎣 Pre-commit hooks: ✅ Configurados"
    else
        echo "🎣 Pre-commit hooks: ❌ No configurados"
    fi

    echo ""
    echo "💡 Comandos útiles:"
    echo "   $0 check-tools    - Verificar herramientas"
    echo "   $0 quick-check    - Auditoría rápida"
    echo "   $0 full-audit     - Auditoría completa"
}

# Procesamiento de argumentos
case "${1:-help}" in
    "update-tools")
        update_tools
        ;;
    "check-tools")
        check_tools
        ;;
    "install-missing")
        install_missing
        ;;
    "clean-reports")
        clean_reports
        ;;
    "clean-cache")
        clean_cache
        ;;
    "clean-all")
        clean_all
        ;;
    "reset-config")
        reset_config
        ;;
    "setup-hooks")
        setup_hooks
        ;;
    "update-github")
        update_github
        ;;
    "quick-check")
        quick_check
        ;;
    "full-audit")
        full_audit
        ;;
    "status")
        show_status
        ;;
    "help"|*)
        show_help
        ;;
esac
