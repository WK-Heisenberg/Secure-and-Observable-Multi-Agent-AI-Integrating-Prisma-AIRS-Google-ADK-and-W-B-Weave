from agents.orchestrator.orchestrator import OrchestratorAgent
from agents.research.research_agent import ResearcherAgent

orchestrator = OrchestratorAgent(color="purple", icon="manage_accounts")
researcher = ResearcherAgent(color="orange", icon="science")

orchestrator.sub_agents = [researcher]

root_agent = orchestrator
