"""
Think-Adapt-Act Agent: Industrial Edition
Architecture: LangGraph Stateful Workflow
Memory: Mem0 (Long-term Context)
Tools: Python REPL, DuckDuckGo Search, File I/O
"""

import os
import sys
import io
import operator
from typing import Annotated, TypedDict, List, Dict, Any, Union
from datetime import datetime
from dotenv import load_dotenv

# Modern Agent Stack
from mem0 import Memory
from langchain_mistralai import ChatMistralAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage, AIMessage
from langchain_core.tools import tool
from langchain_community.tools import DuckDuckGoSearchRun
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.message import add_messages

load_dotenv()

# --- 1. THE "ACT" LAYER (INDUSTRIAL TOOLS) ---

@tool
def web_search(query: str):
    """
    Search the live web using DuckDuckGo. 
    Use this for current events, real-time data, or verifying facts.
    """
    from ddgs import DDGS
    with DDGS() as ddgs:
        results = [r for r in ddgs.text(query, max_results=3)]
        return str(results)

@tool
def python_repl(code: str):
    """
    Executes Python code in a local environment.
    Use for: Algorithms, Complex Math (numpy/sympy), and Data Processing.
    The code must PRINT the result.
    """
    old_stdout = sys.stdout
    new_stdout = io.StringIO()
    sys.stdout = new_stdout
    try:
        exec_globals = {
            "math": __import__("math"), 
            "sympy": __import__("sympy"), 
            "np": __import__("numpy")
        }
        exec(code, exec_globals)
        return new_stdout.getvalue() or "Executed (no output)."
    except Exception as e:
        return f"Error: {e}"
    finally:
        sys.stdout = old_stdout

@tool
def write_file(filename: str, content: str):
    """Writes content to a local file. Use for persistent reports or data."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote to {filename}"
    except Exception as e:
        return f"File Error: {e}"

@tool
def read_file(filename: str):
    """Reads content from a local file."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"File Error: {e}"

@tool
def ask_human(question: str):
    """
    Asks the human user a question when clarification or permission is needed.
    This implements 'Human-in-the-Loop'.
    """
    print(f"\n[AGENT REQUEST]: {question}")
    user_response = input(">> Your Response: ")
    return user_response

# --- 2. THE "THINK" LAYER (STATE & GRAPH) ---

class AgentState(TypedDict):
    """State definition for the LangGraph workflow."""
    messages: Annotated[list, add_messages]
    user_id: str
    memories: str

class TrendyAgent:
    def __init__(self, user_id: str, db_path: str = "mem0.db"):
        self.user_id = user_id
        
        # --- 2. THE "ADAPT" LAYER (MEM0) ---
        self.memory_store = Memory.from_config({
            "llm": {"provider": "openai", "config": {"model": "mistral-tiny"}},
            "vector_store": {"provider": "qdrant", "config": {"path": db_path, "embedding_model_dims": 1024}},
            "embedder": {"provider": "openai", "config": {"model": "mistral-embed"}}
        })

        # LLM Setup
        self.llm = ChatMistralAI(model="mistral-small-latest", api_key=os.getenv("MISTRAL_API_KEY"))
        self.tools = [web_search, python_repl, write_file, read_file, ask_human]
        self.llm_with_tools = self.llm.bind_tools(self.tools)

        # Build the Graph
        self.workflow = self._create_workflow()
        self.app = self.workflow.compile(checkpointer=MemorySaver())

    def _create_workflow(self):
        graph = StateGraph(AgentState)

        # Define Nodes
        graph.add_node("retrieve_memory", self._retrieve_memory)
        graph.add_node("reason", self._reason)
        graph.add_node("action", ToolNode(self.tools))

        # Define Edges
        graph.set_entry_point("retrieve_memory")
        graph.add_edge("retrieve_memory", "reason")
        
        graph.add_conditional_edges(
            "reason",
            self._should_continue,
            {
                "continue": "action",
                "end": END
            }
        )
        graph.add_edge("action", "reason")

        return graph

    def _retrieve_memory(self, state: AgentState):
        """Retrieve context from Mem0."""
        last_message = state["messages"][-1].content
        results = self.memory_store.search(last_message, filters={"user_id": state["user_id"]})
        mem_str = "\n".join([m['memory'] for m in results.get('results', [])])
        return {"memories": mem_str}

    def _reason(self, state: AgentState):
        """Thinking node: decide what to do next."""
        # System message defines the persona and context
        system_msg = SystemMessage(content=f"""
        You are 3sso, a Trendy Industrial AI Agent (Think-Adapt-Act).
        
        ADAPTED USER CONTEXT:
        {state['memories']}
        
        INSTRUCTIONS:
        - Analyze context and use tools (Web Search, REPL, File IO, HITL) when needed.
        - Be concise and accurate.
        - Current Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """)
        
        # Mistral requirement: messages must follow [system]?, [user, assistant, user, assistant]...
        # Tool messages must follow the AIMessage that requested them.
        messages = [system_msg] + state["messages"]
        
        try:
            response = self.llm_with_tools.invoke(messages)
            return {"messages": [response]}
        except Exception as e:
            # Fallback for API errors or rate limits
            print(f"  [Thinking Error]: {e}")
            return {"messages": [AIMessage(content=f"I encountered an error while thinking: {e}")]}

    def _should_continue(self, state: AgentState):
        """Routing logic based on tool calls."""
        last_message = state["messages"][-1]
        if last_message.tool_calls:
            return "continue"
        return "end"

    def run(self, user_input: str):
        """Entry point for the agent."""
        config = {"configurable": {"thread_id": self.user_id}}
        initial_state = {
            "messages": [HumanMessage(content=user_input)],
            "user_id": self.user_id
        }
        
        print(f"\n[User]: {user_input}")
        
        final_state = self.app.invoke(initial_state, config=config)
        response = final_state["messages"][-1].content
        
        # ADAPT: Store back to Mem0
        self.memory_store.add(user_input, user_id=self.user_id)
        self.memory_store.add(response, user_id=self.user_id)
        
        print(f"[Agent]: {response}")
        return response

if __name__ == "__main__":
    agent = TrendyAgent(user_id="trendy_alex")
    agent.run("What's the latest stock price of NVIDIA? Also, save it to a file named 'stocks.txt'.")
