#!/usr/bin/env python3
"""
Main Web Server Entrypoint for the Prisma AIRS Multi-Agent Demo
"""
import logging
import os
import atexit
import asyncio
import weave
import wandb
from dotenv import load_dotenv

# Load environment variables from .env file before other imports
load_dotenv()

# --- Weave/OpenTelemetry Configuration ---
# Important: This must be done before any ADK components are imported
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# Initialize Weave
project_name = os.environ.get("WANDB_PROJECT")
if project_name:
    weave.init(project_name=project_name)

# Encode the WANDB_API_KEY in base64
wandb_api_key = os.environ.get("WANDB_API_KEY")
if wandb_api_key:
    # Basic Auth: https://swagger.io/docs/specification/authentication/basic-authentication/
    auth_header = f"Basic {wandb_api_key}"
    
    project_id = f"{os.environ.get('WANDB_ENTITY')}/{os.environ.get('WANDB_PROJECT')}"

    exporter = OTLPSpanExporter(
        endpoint="https://trace.wandb.ai/otel/v1/traces",
        headers={
            "Authorization": auth_header,
            "project_id": project_id,
        },
    )

    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)

    def shutdown_opentelemetry():
        if "exporter" in globals():
            exporter.shutdown()
        if "tracer_provider" in globals():
            tracer_provider.shutdown()
        if "security_scanner" in globals():
            loop = asyncio.get_event_loop()
            loop.run_until_complete(security_scanner.close_session())
        if wandb.run is not None:
            wandb.finish()

    atexit.register(shutdown_opentelemetry)

# --- End Weave/OpenTelemetry Configuration ---

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- ADK Imports ---
try:
    import google.adk as adk
    from agents.orchestrator.orchestrator import OrchestratorAgent
    from agents.research.research_agent import ResearcherAgent
    from agents.evaluation.evaluation_agent import EvaluationAgent
    from agents.dashboard.dashboard_agent import SecurityDashboardAgent
    from google.adk.cli.utils.base_agent_loader import BaseAgentLoader
    from google.adk.apps.app import App
    from google.adk.cli.adk_web_server import AdkWebServer
    from google.adk.sessions.in_memory_session_service import InMemorySessionService
    from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
    from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
    from google.adk.auth.credential_service.in_memory_credential_service import InMemoryCredentialService
    from google.adk.evaluation.in_memory_eval_sets_manager import InMemoryEvalSetsManager
    from google.adk.evaluation.local_eval_set_results_manager import LocalEvalSetResultsManager

except ImportError as e:
    logger.error(f"Failed to import necessary modules. Ensure google-adk is installed. Error: {e}")
    exit(1)

# --- Agent Loader ---
class SingleAppLoader(BaseAgentLoader):
    def __init__(self, app_instance):
        self._app = app_instance

    def load_agent(self, agent_name: str):
        # It will be called with the app name.
        return self._app

    def list_agents(self) -> list[str]:
        return [self._app.name]

# --- Agent Initialization ---
orchestrator = OrchestratorAgent()
researcher = ResearcherAgent()
evaluation_agent = EvaluationAgent(name="EvaluationAgent")
dashboard_agent = SecurityDashboardAgent(name="SecurityDashboardAgent")
orchestrator.sub_agents = [researcher, evaluation_agent, dashboard_agent]

app_instance = App(
    name="Prisma AIRS Multi-Agent Demo",
    root_agent=orchestrator
)

# --- ADK Web Server Initialization ---
agent_loader = SingleAppLoader(app_instance)
session_service = InMemorySessionService()
artifact_service = InMemoryArtifactService()
memory_service = InMemoryMemoryService()
credential_service = InMemoryCredentialService()
eval_sets_manager = InMemoryEvalSetsManager()
eval_set_results_manager = LocalEvalSetResultsManager(agents_dir=".") # dummy dir

adk_web_server = AdkWebServer(
    agent_loader=agent_loader,
    session_service=session_service,
    artifact_service=artifact_service,
    memory_service=memory_service,
    credential_service=credential_service,
    eval_sets_manager=eval_sets_manager,
    eval_set_results_manager=eval_set_results_manager,
    agents_dir="." # dummy dir
)

# --- FastAPI App Initialization ---
import pathlib
import google.adk.cli

# Programmatically find the ADK web assets directory. This is a robust way
# to ensure the UI is served correctly, regardless of where the package is installed.
web_assets_dir = pathlib.Path(google.adk.cli.__file__).parent / "browser"
# The ADK web server can find its own assets when web_assets_dir is not provided.
app = adk_web_server.get_fast_api_app(web_assets_dir=str(web_assets_dir))

from security.prisma_airs_http import security_scanner