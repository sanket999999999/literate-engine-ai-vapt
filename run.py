"""Start the vapt-ai dashboard and API.

    python run.py                 # http://127.0.0.1:8000
    python run.py --port 9000 --reload
"""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="Reload on code changes.")
    args = parser.parse_args()

    uvicorn.run(
        "vapt.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
