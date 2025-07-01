# Auditorías de Código - QuantumARK

Este directorio contiene todas las auditorías automatizadas del proyecto QuantumARK para garantizar la calidad, seguridad y mantenibilidad del código.

## Estructura de Auditorías

### 🔒 Seguridad
- **bandit**: Análisis de vulnerabilidades de seguridad
- **semgrep**: Análisis estático avanzado de seguridad
- **safety**: Verificación de dependencias vulnerables
- **pip-audit**: Auditoría de vulnerabilidades en paquetes
- **checkov**: Análisis de infraestructura como código

### 🔍 Calidad de Código
- **mypy**: Verificación de tipos estáticos
- **pyright**: Análisis de tipos alternativo
- **pylint**: Análisis completo de calidad de código
- **prospector**: Análisis integral de múltiples herramientas
- **radon**: Métricas de complejidad ciclomática
- **lizard**: Análisis de complejidad de funciones

### 🎨 Formato y Estilo
- **flake8**: Verificación de estilo PEP 8
- **black**: Formateo automático de código
- **isort**: Organización de imports

### 🧪 Testing
- **pytest**: Ejecución de tests
- **coverage**: Medición de cobertura de código

### ⚙️ Automatización
- **pre-commit**: Hooks de pre-commit para CI/CD

## Cómo Ejecutar las Auditorías

```bash
# Ejecutar todas las auditorías
./run_full_audit.sh

# Ejecutar auditorías específicas
./run_security_audit.sh
./run_quality_audit.sh
./run_format_audit.sh
./run_testing_audit.sh
```

## Reportes

Los reportes se generan en formato:
- JSON para integración con CI/CD
- HTML para revisión humana
- Markdown para documentación

Fecha de última auditoría: $(date)
