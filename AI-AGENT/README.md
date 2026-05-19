# 3sso: Industrial Think-Adapt-Act AI Agent

3sso is an industrial-grade AI agent architecture that combines state-of-the-art tools and frameworks used by leading AI engineering teams. It follows the Think-Adapt-Act cycle using a stateful workflow.

## Tech Stack

- **Orchestration**: LangGraph - A framework for building stateful, multi-turn agentic workflows.
- **Memory Layer**: Mem0 - Persistent, long-term memory that evolves with every interaction.
- **LLM**: Mistral AI - High-performance reasoning via the `mistral-small-latest` model.
- **Vector DB**: Qdrant - Local vector storage for fast semantic memory retrieval.
- **Package Manager**: uv - The fastest Python dependency manager.

## Advanced Architecture

The agent is built as a State Machine with the following nodes:
1. **Retrieve (Adapt)**: Pulls relevant context from Mem0 based on the user's query.
2. **Reason (Think)**: The LLM analyzes the query + memories to decide on a plan.
3. **Action (Act)**: Executes tools and feeds results back into the loop.

### Integrated Tools
- **Web Search**: Real-time information retrieval via DuckDuckGo.
- **Python REPL**: Advanced scientific computing and algorithmic solving.
- **File I/O**: Ability to read and write local files for data persistence.
- **Human-in-the-Loop (HITL)**: A dedicated `ask_human` tool for permission and clarification.

## Getting Started

Follow these steps to set up and run 3sso on your local machine.

### 1. Install uv
This project uses `uv` for ultra-fast dependency management. If you don't have it installed:

**Windows:**
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS/Linux:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Setup Environment
Create a `.env` file in the root directory and add your Mistral API key:
```env
MISTRAL_API_KEY=your_mistral_api_key_here
```

### 3. Installation & Initialization
If you have just cloned the repository, run:
```bash
uv sync
```
This will automatically create a virtual environment and install all required dependencies.

### 4. Usage
Run the main demonstration script:
```bash
uv run python main.py
```

## Future Enhancements & Roadmap

To evolve this agent into a next-generation autonomous system, the following enhancements are planned:

### 1. Secure Execution Sandbox
- **Dockerized REPL**: Move the `python_repl` tool into a transient Docker container to execute code in complete isolation.
- **Resource Limiting**: Implement strict CPU and memory limits for tool execution.

### 2. Multi-Agent Swarm Orchestration
- **Specialized Agents**: Transition from a single agent to a "Swarm" of specialized agents (e.g., a Researcher Agent and a Developer Agent).
- **Supervisor Node**: Add a supervisor node to LangGraph to manage task delegation.

### 3. Graph-Based Memory Reasoning
- **Knowledge Graph Integration**: Combine Mem0's vector memory with a Graph Database (like Neo4j) for complex relationship reasoning.

### 4. Multi-Modal Interaction
- **Vision & Audio**: Integrate Mistral's vision models and Whisper for audio support.

### 5. Advanced Observability
- **LangSmith Integration**: Full tracing of the agent's reasoning process for debugging and optimization.

## License
MIT
