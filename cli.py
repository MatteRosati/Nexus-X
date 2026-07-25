import argparse
import asyncio
import os
import sys
from pathlib import Path

# Setup defaults for CLI if not in environment
os.environ.setdefault("DATABASE_URL", "sqlite:///./database/easm.db")
os.environ.setdefault("EASM_ALLOWED_DOMAINS", "")
os.environ.setdefault("ALLOW_ARBITRARY_TARGETS", "true")
os.environ.setdefault("APP_API_KEY", "cli-mode-no-key-required-xxxxxxxxxxxxxx")

from app.core.domain import normalize_domain, DomainValidationError
from app.db.base import Base
from app.db.models import Scan
from app.db.session import SessionLocal, engine
from app.engine.orchestrator import process_scan
from sqlalchemy.orm import selectinload
from app.report.generator import render_report

async def run_cli_scan(domain_input: str, output_file: str = None):
    try:
        domain = normalize_domain(domain_input)
    except DomainValidationError as e:
        print(f"[-] Invalid domain: {e}")
        sys.exit(1)

    print(f"[*] Starting Nexus-X CLI scan for target: {domain}")
    
    # Ensure database exists
    Path("./database").mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # 1. Create scan in 'running' status to prevent background workers from stealing it
    with SessionLocal() as db:
        scan = Scan(target=domain, status="running", summary={})
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    
    print(f"[*] Scan ID created: {scan_id}")
    print("[*] Executing collectors in parallel... (This might take a few moments depending on crt.sh and network latency)")

    # 2. Run the orchestrator synchronously
    await process_scan(scan_id)

    # 3. Fetch results and generate report
    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).options(
            selectinload(Scan.assets), 
            selectinload(Scan.findings), 
            selectinload(Scan.collector_runs)
        ).first()

        if scan.status in ("completed", "partial_failed"):
            print(f"[+] Scan finished with status: {scan.status}")
            print(f"    - Assets found: {scan.summary.get('assets', 0)}")
            print(f"    - Findings generated: {scan.summary.get('findings', 0)}")
            
            html = render_report(scan)
            
            if not output_file:
                output_file = f"report_{domain.replace('.', '_')}.html"
                
            with open(output_file, "w") as f:
                f.write(html)
                
            print(f"\n[✓] Success! HTML Report generated and saved to: {os.path.abspath(output_file)}")
        else:
            print(f"[-] Scan failed with status: {scan.status}")
            print(f"[-] Error: {scan.error}")

def main():
    parser = argparse.ArgumentParser(description="Nexus-X EASM CLI Tool")
    parser.add_argument("domain", help="The target domain to scan (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Path for the output HTML report", default=None)
    
    args = parser.parse_args()
    
    asyncio.run(run_cli_scan(args.domain, args.output))

if __name__ == "__main__":
    main()
