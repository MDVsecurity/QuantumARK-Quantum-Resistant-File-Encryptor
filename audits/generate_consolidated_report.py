#!/usr/bin/env python3
"""
Generador de reporte consolidado de auditorías para QuantumARK
Combina todos los resultados de las herramientas de análisis en un reporte HTML
"""

import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List


class AuditReportGenerator:
    def __init__(self, reports_dir: str):
        self.reports_dir = Path(reports_dir)
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def load_json_report(self, file_path: Path) -> Dict[str, Any]:
        """Cargar reporte JSON si existe"""
        try:
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            return {}
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error cargando {file_path}: {e}")
            return {}

    def load_text_report(self, file_path: Path) -> str:
        """Cargar reporte de texto si existe"""
        try:
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
            return "Reporte no disponible"
        except Exception as e:
            return f"Error cargando reporte: {e}"

    def count_issues(self, data: Dict[str, Any], tool: str) -> int:
        """Contar issues según el formato de cada herramienta"""
        if tool == "bandit":
            return len(data.get("results", []))
        elif tool == "semgrep":
            return len(data.get("results", []))
        elif tool == "safety":
            return len(data.get("vulnerabilities", []))
        elif tool == "pip-audit":
            return len(data.get("vulnerabilities", []))
        elif tool == "flake8":
            return len(data) if isinstance(data, list) else 0
        elif tool == "prospector":
            return len(data.get("messages", []))
        elif tool == "pylint":
            return len([msg for msg in data if msg.get("type") == "error"])
        return 0

    def get_severity_summary(self, data: Dict[str, Any], tool: str) -> Dict[str, int]:
        """Obtener resumen de severidad"""
        severity_map = {"high": 0, "medium": 0, "low": 0, "info": 0}

        if tool == "bandit":
            for result in data.get("results", []):
                sev = result.get("issue_severity", "").lower()
                if sev in severity_map:
                    severity_map[sev] += 1
        elif tool == "semgrep":
            for result in data.get("results", []):
                sev = result.get("extra", {}).get("severity", "").lower()
                if sev in severity_map:
                    severity_map[sev] += 1

        return severity_map

    def generate_html_report(self) -> str:
        """Generar reporte HTML consolidado"""

        # Cargar todos los reportes
        security_reports = {
            "bandit": self.load_json_report(
                self.reports_dir / "security" / "bandit_report.json"
            ),
            "semgrep": self.load_json_report(
                self.reports_dir / "security" / "semgrep_report.json"
            ),
            "safety": self.load_json_report(
                self.reports_dir / "security" / "safety_report.json"
            ),
            "pip-audit": self.load_json_report(
                self.reports_dir / "security" / "pip_audit_report.json"
            ),
        }

        quality_reports = {
            "pylint": self.load_json_report(
                self.reports_dir / "quality" / "pylint_report.json"
            ),
            "prospector": self.load_json_report(
                self.reports_dir / "quality" / "prospector_report.json"
            ),
            "radon_cc": self.load_json_report(
                self.reports_dir / "quality" / "radon_cc_report.json"
            ),
            "radon_mi": self.load_json_report(
                self.reports_dir / "quality" / "radon_mi_report.json"
            ),
            "mypy": self.load_text_report(
                self.reports_dir / "quality" / "mypy_report.txt"
            ),
        }

        formatting_reports = {
            "flake8": self.load_json_report(
                self.reports_dir / "formatting" / "flake8_report.json"
            ),
            "black": self.load_text_report(
                self.reports_dir / "formatting" / "black_report.txt"
            ),
            "isort": self.load_text_report(
                self.reports_dir / "formatting" / "isort_report.txt"
            ),
        }

        # Generar HTML
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Auditoría - QuantumARK</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .section {{ padding: 20px; border-bottom: 1px solid #eee; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-number {{ font-size: 2em; font-weight: bold; color: #495057; }}
        .metric-label {{ color: #6c757d; margin-top: 5px; }}
        .status-good {{ color: #28a745; }}
        .status-warning {{ color: #ffc107; }}
        .status-error {{ color: #dc3545; }}
        .tool-section {{ margin: 20px 0; }}
        .tool-header {{ background: #e9ecef; padding: 15px; border-radius: 5px; font-weight: bold; }}
        .tool-content {{ background: #f8f9fa; padding: 15px; border: 1px solid #dee2e6; border-top: none; }}
        pre {{ background: #ffffff; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
        .summary-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .summary-table th, .summary-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .summary-table th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Reporte de Auditoría - QuantumARK</h1>
            <p>Análisis completo de seguridad, calidad y formato del código</p>
            <p><strong>Generado:</strong> {self.timestamp}</p>
        </div>

        <div class="section">
            <h2>📊 Resumen Ejecutivo</h2>
            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-number status-error">{self.count_issues(security_reports.get('bandit', {}), 'bandit')}</div>
                    <div class="metric-label">Vulnerabilidades de Seguridad</div>
                </div>
                <div class="metric-card">
                    <div class="metric-number status-warning">{self.count_issues(quality_reports.get('pylint', []), 'pylint')}</div>
                    <div class="metric-label">Issues de Calidad</div>
                </div>
                <div class="metric-card">
                    <div class="metric-number status-good">{len([f for f in os.listdir(self.reports_dir) if f.endswith('.json') or f.endswith('.txt')])}</div>
                    <div class="metric-label">Herramientas Ejecutadas</div>
                </div>
                <div class="metric-card">
                    <div class="metric-number status-good">{len([f for f in Path('/Users/brx/Documents/QuantumARK').glob('*.py')])}</div>
                    <div class="metric-label">Archivos Python</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🔒 Análisis de Seguridad</h2>

            <div class="tool-section">
                <div class="tool-header">🛡️ Bandit - Vulnerabilidades de Seguridad</div>
                <div class="tool-content">
                    <p><strong>Issues encontrados:</strong> {self.count_issues(security_reports.get('bandit', {}), 'bandit')}</p>
                    {self._generate_bandit_summary(security_reports.get('bandit', {}))}
                </div>
            </div>

            <div class="tool-section">
                <div class="tool-header">🔍 Semgrep - Análisis Estático</div>
                <div class="tool-content">
                    <p><strong>Issues encontrados:</strong> {self.count_issues(security_reports.get('semgrep', {}), 'semgrep')}</p>
                    {self._generate_semgrep_summary(security_reports.get('semgrep', {}))}
                </div>
            </div>

            <div class="tool-section">
                <div class="tool-header">🛡️ Safety - Dependencias Vulnerables</div>
                <div class="tool-content">
                    <p><strong>Vulnerabilidades:</strong> {self.count_issues(security_reports.get('safety', {}), 'safety')}</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🔍 Análisis de Calidad</h2>

            <div class="tool-section">
                <div class="tool-header">📋 Pylint - Análisis de Código</div>
                <div class="tool-content">
                    <p><strong>Issues encontrados:</strong> {len(quality_reports.get('pylint', []))}</p>
                    {self._generate_pylint_summary(quality_reports.get('pylint', []))}
                </div>
            </div>

            <div class="tool-section">
                <div class="tool-header">🔬 MyPy - Verificación de Tipos</div>
                <div class="tool-content">
                    <pre>{quality_reports.get('mypy', 'No disponible')[:500]}{'...' if len(quality_reports.get('mypy', '')) > 500 else ''}</pre>
                </div>
            </div>

            <div class="tool-section">
                <div class="tool-header">📈 Radon - Complejidad Ciclomática</div>
                <div class="tool-content">
                    {self._generate_radon_summary(quality_reports.get('radon_cc', {}))}
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎨 Análisis de Formato</h2>

            <div class="tool-section">
                <div class="tool-header">📏 Flake8 - Estilo PEP 8</div>
                <div class="tool-content">
                    <p><strong>Issues encontrados:</strong> {self.count_issues(formatting_reports.get('flake8', {}), 'flake8')}</p>
                </div>
            </div>

            <div class="tool-section">
                <div class="tool-header">⚫ Black - Formato de Código</div>
                <div class="tool-content">
                    <pre>{formatting_reports.get('black', 'No disponible')[:300]}{'...' if len(formatting_reports.get('black', '')) > 300 else ''}</pre>
                </div>
            </div>

            <div class="tool-section">
                <div class="tool-header">📦 isort - Orden de Imports</div>
                <div class="tool-content">
                    <pre>{formatting_reports.get('isort', 'No disponible')[:300]}{'...' if len(formatting_reports.get('isort', '')) > 300 else ''}</pre>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>📈 Recomendaciones</h2>
            <ul>
                <li>✅ Revisar y corregir las vulnerabilidades de seguridad encontradas por Bandit</li>
                <li>✅ Implementar type hints siguiendo las recomendaciones de MyPy</li>
                <li>✅ Aplicar las correcciones de formato sugeridas por Black e isort</li>
                <li>✅ Reducir la complejidad ciclomática en funciones marcadas por Radon</li>
                <li>✅ Implementar tests unitarios para mejorar la cobertura</li>
                <li>✅ Configurar pre-commit hooks para automatizar las verificaciones</li>
            </ul>
        </div>

        <div class="section">
            <h2>📁 Archivos de Reporte</h2>
            <p>Todos los reportes detallados están disponibles en:</p>
            <ul>
                <li><strong>Seguridad:</strong> audits/reports/security/</li>
                <li><strong>Calidad:</strong> audits/reports/quality/</li>
                <li><strong>Formato:</strong> audits/reports/formatting/</li>
                <li><strong>Testing:</strong> audits/reports/testing/</li>
            </ul>
        </div>
    </div>
</body>
</html>
        """

        return html

    def _generate_bandit_summary(self, data: Dict[str, Any]) -> str:
        """Generar resumen de Bandit"""
        if not data or not data.get("results"):
            return "<p>✅ No se encontraron vulnerabilidades de seguridad</p>"

        severity_counts = self.get_severity_summary(data, "bandit")
        return f"""
        <table class="summary-table">
            <tr><th>Severidad</th><th>Cantidad</th></tr>
            <tr><td>Alto</td><td class="status-error">{severity_counts.get('high', 0)}</td></tr>
            <tr><td>Medio</td><td class="status-warning">{severity_counts.get('medium', 0)}</td></tr>
            <tr><td>Bajo</td><td class="status-good">{severity_counts.get('low', 0)}</td></tr>
        </table>
        """

    def _generate_semgrep_summary(self, data: Dict[str, Any]) -> str:
        """Generar resumen de Semgrep"""
        if not data or not data.get("results"):
            return "<p>✅ No se encontraron issues de seguridad</p>"
        return f"<p>Se encontraron {len(data.get('results', []))} potenciales issues de seguridad</p>"

    def _generate_pylint_summary(self, data: List[Any]) -> str:
        """Generar resumen de Pylint"""
        if not data:
            return "<p>✅ No se encontraron issues de calidad</p>"

        types = {}
        for msg in data:
            msg_type = msg.get("type", "unknown")
            types[msg_type] = types.get(msg_type, 0) + 1

        summary = "<table class='summary-table'><tr><th>Tipo</th><th>Cantidad</th></tr>"
        for msg_type, count in types.items():
            summary += f"<tr><td>{msg_type}</td><td>{count}</td></tr>"
        summary += "</table>"
        return summary

    def _generate_radon_summary(self, data: Dict[str, Any]) -> str:
        """Generar resumen de Radon"""
        if not data:
            return "<p>No hay datos de complejidad disponibles</p>"

        total_functions = 0
        complex_functions = 0

        for file_data in data.values():
            if isinstance(file_data, list):
                for func in file_data:
                    total_functions += 1
                    if func.get("complexity", 0) > 10:
                        complex_functions += 1

        return f"""
        <p><strong>Total de funciones analizadas:</strong> {total_functions}</p>
        <p><strong>Funciones con alta complejidad (>10):</strong> {complex_functions}</p>
        """


def main():
    """Función principal"""
    reports_dir = "/Users/brx/Documents/QuantumARK/audits/reports"
    generator = AuditReportGenerator(reports_dir)

    # Generar reporte HTML
    html_content = generator.generate_html_report()

    # Guardar reporte
    output_file = Path(reports_dir) / "consolidated_report.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"✅ Reporte consolidado generado: {output_file}")

    # Generar también un resumen en JSON
    summary = {
        "timestamp": generator.timestamp,
        "project": "QuantumARK",
        "total_tools": 17,
        "reports_generated": len(list(Path(reports_dir).rglob("*"))),
        "status": "completed",
    }

    with open(Path(reports_dir) / "audit_summary.json", "w") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()
