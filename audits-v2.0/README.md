# QuantumARK - Sistema de Auditorías v2.0

## Descripción

Este directorio contiene el sistema de auditorías modernizado para QuantumARK v2.0, que incluye herramientas avanzadas de seguridad, análisis de código y testing automatizado.

## Estructura

```
audits-v2.0/
├── README.md                    # Este archivo
├── requirements.txt             # Dependencias para auditorías
├── config/                      # Configuraciones de herramientas
│   ├── .bandit                 # Configuración de Bandit
│   ├── .flake8                 # Configuración de Flake8
│   ├── .pylintrc               # Configuración de Pylint
│   ├── mypy.ini                # Configuración de MyPy
│   └── pytest.ini             # Configuración de Pytest
├── scripts/                     # Scripts de automatización
│   ├── run_security_audit.sh   # Auditoría de seguridad
│   ├── run_code_quality.sh     # Análisis de calidad de código
│   ├── run_tests.sh            # Ejecución de tests
│   └── run_full_audit.sh       # Auditoría completa
├── workflows/                   # Workflows para CI/CD
│   └── audit-pipeline.yml      # Pipeline de auditorías
└── reports/                     # Directorio para reportes
    ├── security/
    ├── quality/
    └── tests/
```

## Herramientas Incluidas

### Seguridad
- **Bandit**: Análisis de vulnerabilidades de seguridad en Python
- **Safety**: Verificación de dependencias vulnerables
- **Semgrep**: Análisis estático de seguridad avanzado
- **pip-audit**: Auditoría de dependencias

### Calidad de Código
- **Pylint**: Análisis estático integral
- **Flake8**: Verificación de estilo y complejidad
- **Black**: Formateo automático de código
- **isort**: Ordenamiento de imports
- **MyPy**: Verificación de tipos
- **Pyright**: Verificación de tipos avanzada

### Testing
- **Pytest**: Framework de testing
- **Coverage**: Medición de cobertura de código
- **Pytest-cov**: Integración de cobertura con pytest

### Métricas y Análisis
- **Radon**: Análisis de complejidad ciclomática
- **Lizard**: Análisis de complejidad de funciones
- **Prospector**: Análisis agregado de calidad

## Uso Rápido

```bash
# Ejecutar auditoría completa
./scripts/run_full_audit.sh

# Solo auditoría de seguridad
./scripts/run_security_audit.sh

# Solo análisis de calidad
./scripts/run_code_quality.sh

# Solo tests
./scripts/run_tests.sh
```

## Instalación

```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar pre-commit hooks (opcional)
pre-commit install
```

## Versión

**v2.0** - Sistema modernizado con herramientas actualizadas y mejores prácticas de DevSecOps.
