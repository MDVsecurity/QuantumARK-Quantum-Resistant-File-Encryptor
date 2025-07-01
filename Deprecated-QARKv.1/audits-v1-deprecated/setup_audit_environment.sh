#!/bin/bash
# Script de configuración del entorno de auditoría para QuantumARK

PROJECT_ROOT="/Users/brx/Documents/QuantumARK"
AUDIT_DIR="$PROJECT_ROOT/audits"

echo "🚀 Configurando entorno de auditoría para QuantumARK"
echo "=================================================="

cd "$PROJECT_ROOT"

# Verificar Python
echo "🐍 Verificando Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado. Por favor instálalo primero."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python $PYTHON_VERSION encontrado"

# Crear entorno virtual si no existe
if [ ! -d "audit_env" ]; then
    echo "📦 Creando entorno virtual..."
    python3 -m venv audit_env
fi

# Activar entorno virtual
echo "🔄 Activando entorno virtual..."
source audit_env/bin/activate

# Actualizar pip
echo "⬆️ Actualizando pip..."
pip install --upgrade pip

# Instalar herramientas de auditoría
echo "🛠️ Instalando herramientas de auditoría..."
pip install -r "$AUDIT_DIR/requirements.txt"

# Verificar instalaciones
echo ""
echo "🔍 Verificando instalaciones..."
tools=(
    "bandit"
    "semgrep"
    "safety"
    "pip-audit"
    "pylint"
    "mypy"
    "flake8"
    "black"
    "isort"
    "prospector"
    "radon"
    "pytest"
    "coverage"
    "pre-commit"
)

failed_tools=()
for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool instalado correctamente"
    else
        echo "❌ $tool no encontrado"
        failed_tools+=("$tool")
    fi
done

# Configurar pre-commit
echo ""
echo "⚙️ Configurando pre-commit hooks..."
cp "$AUDIT_DIR/.pre-commit-config.yaml" "$PROJECT_ROOT/.pre-commit-config.yaml"
pre-commit install

# Crear directorio .github/workflows si no existe
echo "📁 Configurando GitHub Actions..."
mkdir -p "$PROJECT_ROOT/.github/workflows"
cp "$AUDIT_DIR/github_workflow.yml" "$PROJECT_ROOT/.github/workflows/audit.yml"

# Crear symlinks para configuraciones
echo "🔗 Creando enlaces simbólicos para configuraciones..."
ln -sf "$AUDIT_DIR/.flake8" "$PROJECT_ROOT/.flake8"
ln -sf "$AUDIT_DIR/mypy.ini" "$PROJECT_ROOT/mypy.ini"
ln -sf "$AUDIT_DIR/.bandit" "$PROJECT_ROOT/.bandit"
ln -sf "$AUDIT_DIR/pytest.ini" "$PROJECT_ROOT/pytest.ini"

# Generar script de activación del entorno
cat > "$PROJECT_ROOT/activate_audit_env.sh" << 'EOF'
#!/bin/bash
# Script para activar el entorno de auditoría
source audit_env/bin/activate
echo "🔍 Entorno de auditoría activado"
echo "Ejecuta './audits/run_full_audit.sh' para realizar una auditoría completa"
EOF

chmod +x "$PROJECT_ROOT/activate_audit_env.sh"

echo ""
echo "✅ Configuración del entorno de auditoría completada!"
echo ""
echo "📋 Resumen:"
echo "  - Entorno virtual creado en: audit_env/"
echo "  - Herramientas instaladas: ${#tools[@]}"
echo "  - Pre-commit hooks configurados"
echo "  - GitHub Actions workflow creado"
echo ""
echo "🔧 Para usar el entorno de auditoría:"
echo "  1. Activa el entorno: source ./activate_audit_env.sh"
echo "  2. Ejecuta auditoría completa: ./audits/run_full_audit.sh"
echo "  3. O ejecuta auditorías específicas:"
echo "     - ./audits/run_security_audit.sh"
echo ""
echo "🌐 Los reportes se generarán en: audits/reports/"

if [ ${#failed_tools[@]} -gt 0 ]; then
    echo ""
    echo "⚠️ Herramientas que fallaron en la instalación:"
    for tool in "${failed_tools[@]}"; do
        echo "  - $tool"
    done
    echo ""
    echo "Puedes instalarlas manualmente con:"
    echo "  pip install ${failed_tools[*]}"
fi

echo ""
echo "=================================================="
echo "✨ ¡Entorno de auditoría listo para usar!"
