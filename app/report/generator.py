from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.db.models import Scan

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "web" / "templates"
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True, default=True),
)


def render_report(scan: Scan) -> str:
    template = _env.get_template("report.html")
    findings = sorted(scan.findings, key=lambda item: (-item.severity, item.title))
    assets = sorted(scan.assets, key=lambda item: (item.asset_type, item.value))
    collectors = sorted(scan.collector_runs, key=lambda item: item.started_at)
    return template.render(scan=scan, findings=findings, assets=assets, collectors=collectors)
