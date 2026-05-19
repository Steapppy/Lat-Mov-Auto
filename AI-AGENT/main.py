"""
Trendy Agent Entry Point
Architecture: LangGraph + Mem0 + DuckDuckGo
"""

import os
from agent import TrendyAgent
from dotenv import load_dotenv

def main():
    load_dotenv()
    
    # Mem0 Internal Config
    os.environ["OPENAI_API_KEY"] = os.getenv("MISTRAL_API_KEY")
    os.environ["OPENAI_BASE_URL"] = "https://api.mistral.ai/v1"

    # 2. Initialize the Agent
    # Each user_id gets its own isolated memory space.
    user_id = "test_pioneer"
    print(f"--- Welcome to 3sso: The Industrial-Grade AI Agent (User: {user_id}) ---")
    agent = TrendyAgent(user_id=user_id)

    # Multi-turn interaction demonstrating Web Search, Memory, and File I/O
    print("\n[Scenario: Market Research]")
    
    # 1. Web Search + Memory
    agent.run("Hi, I'm Alex. Can you find the current CEO of Mistral AI and what their latest model is?")

    # 2. File I/O + Memory Reasoning
    agent.run("Now, write a summary of that information into a file called 'mistral_info.txt'.")

    # 3. Verification of File I/O
    print("\n[Scenario: Verification]")
    agent.run("Can you read the content of 'mistral_info.txt' and tell me if you remember my name?")

    print("\n--- 🏁 Agent Session Complete ---")

if __name__ == "__main__":
    main()
