import argparse
import asyncio
import json

from app.collectors.censys import collect
from app.core.domain import normalize_domain


async def run(domain: str) -> None:
    result = await collect(domain)
    print(json.dumps({"metadata": result.metadata, "assets": len(result.assets), "findings": len(result.findings)}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the configured Censys Platform API collector. This may consume API credits.")
    parser.add_argument("domain", help="Authorized domain to query")
    args = parser.parse_args()
    asyncio.run(run(normalize_domain(args.domain)))


if __name__ == "__main__":
    main()
