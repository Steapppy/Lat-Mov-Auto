"""
Entry point for the C2 Attack-Chain Agent.
Usage:
  uv run python c2_main.py 10.0.2.0/24
  uv run python c2_main.py 10.0.2.0/24 --session my-pentest
"""

import sys
import os
import argparse
from dotenv import load_dotenv

def main():
    load_dotenv()

    # Mem0 / OpenAI compat shim (used by base agent, not needed here but kept for env parity)
    if os.getenv("MISTRAL_API_KEY"):
        os.environ.setdefault("OPENAI_API_KEY", os.getenv("MISTRAL_API_KEY"))
        os.environ.setdefault("OPENAI_BASE_URL", "https://api.mistral.ai/v1")

    parser = argparse.ArgumentParser(description="C2 autonomous attack-chain agent")
    parser.add_argument("subnet", help="Target subnet CIDR, e.g. 10.0.2.0/24")
    parser.add_argument("--session", default="c2-session", help="LangGraph session/thread ID")
    parser.add_argument("--server", default=None, help="Override C2 server URL (default: http://127.0.0.1:8080)")
    args = parser.parse_args()

    if args.server:
        os.environ["C2_SERVER_URL"] = args.server

    from c2_agent import C2Agent

    agent = C2Agent()
    result = agent.run(args.subnet, session_id=args.session)

    print(f"\n{'='*60}")
    print("[C2 Agent] Final report:")
    print(result)


if __name__ == "__main__":
    main()
