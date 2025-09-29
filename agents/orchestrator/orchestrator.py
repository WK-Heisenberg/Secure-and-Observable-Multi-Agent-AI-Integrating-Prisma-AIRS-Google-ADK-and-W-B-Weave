#!/usr/bin/env python3
"""
Secure Orchestrator Agent with Prisma AIRS Integration
"""
import logging
import re
from typing import AsyncGenerator, Optional

from google.adk.agents.base_agent import BaseAgent as Agent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.adk.models.llm_request import LlmRequest
from google.genai import types

# Import secure base agent
from agents.secure_base_agent import SecureBaseAgent

# Configure logging
logger = logging.getLogger(__name__)

class OrchestratorAgent(SecureBaseAgent):
    """
    Multi-Agent Orchestrator with Prisma AIRS Security Integration.
    Inherits from SecureBaseAgent to get automatic I/O scanning.
    This agent routes requests to specialized agents or handles them directly.
    """

    def __init__(self, name: str = "OrchestratorAgent", color: str = "blue", icon: str = "group_work", verbose: bool = False):
        super().__init__(
            name=name,
            color=color,
            icon=icon,
            verbose=verbose,
            model="gemini-2.5-flash-lite",
            instruction=(
                "You are the orchestrator for the Prisma AIRS Multi-Agent Demo, a secure multi-agent research assistant. Your primary role is to analyze user requests and route them to the appropriate specialist agent or handle them directly.\n\n"
                "This application showcases the integration of Prisma Cloud's AI Runtime Security (AIRS) to protect AI-powered applications. All interactions with this application, including your responses, are scanned for threats in real-time.\n\n"
                "Key Capabilities:\n"
                "- **Delegate Research Tasks:** If the user's request requires real-time information, web research, or knowledge of recent events, you MUST delegate it to the 'ResearcherAgent'.\n"
                "- **Handle Simple Conversation:** For all other tasks, like simple conversation ('hello', 'how are you'), respond directly in a friendly and helpful manner.\n"
                "- **Handle Evaluation:** If the user's response is 'yes' or 'no', you MUST delegate it to the 'EvaluationAgent'.\n"
                "- **Display Security Dashboard:** If the user asks to see the security dashboard, you MUST delegate it to the 'SecurityDashboardAgent'.\n"
                "- **Explain Your Role:** If asked about your capabilities ('what can you do?', 'who are you?'), you must describe your role as the orchestrator for the Prisma AIRS Multi-Agent Demo. Explain that this application demonstrates how to build secure and scalable AI applications by routing tasks between different AI agents, all while being protected by Prisma AIRS. You can also mention that you can either answer simple conversational questions or delegate complex research to a specialized researcher agent. Do not describe yourself as a generic large language model."
            )
        )
        logger.info(f"Initialized {name} with security scanning and delegation logic.")

    async def _secure_agent_logic(
        self, ctx: InvocationContext, user_input: str
    ) -> AsyncGenerator[Event, None]:
        """
        Execute secure orchestration workflow.
        'user_input' is already scanned and approved.
        All yielded events will be scanned before being sent.
        """
        if self.verbose:
            yield self._create_log_event(f"🧠 [{self.name}] Analyzing query: '{user_input[:30]}...", author=self.name)

        # Check for capability questions first, as this is a common query.
        capability_pattern = re.compile(r"(what\s+(can|are|is)\s+(you|this|app's|this app)\s+(do|capabilities|capbailities|capabilites)|who are you)", re.IGNORECASE)
        if capability_pattern.search(user_input):
            response_text = (
                "### Prisma AIRS Multi-Agent Demo\n\n"
                "This is a secure multi-agent research assistant that showcases the integration of **Prisma Cloud's AI Runtime Security (AIRS)** to protect AI-powered applications. All interactions with this application, including this response, are scanned for threats in real-time.\n\n"
                "--- \n\n"
                "#### My Role as Orchestrator\n\n"
                "My primary role is to act as an **orchestrator**. I analyze your requests and route them to the appropriate specialist agent or handle them directly. \n\n"
                "*   For simple conversational questions, I will answer them myself.\n"
                "*   For more complex research tasks, I will delegate them to a specialized **'ResearcherAgent'**."
            )
            yield Event(
                author=f"{self.name}|{self.color}|{self.icon}",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=response_text)]
                )
            )
            return

        # Use a smaller, faster model for routing to keep the conversation snappy.
        routing_model = "gemini-2.5-flash-lite"
        
        # Create a specific instruction for the routing decision.
        routing_instruction = (
            "You are a routing agent. Your job is to classify the user's request into one of the following categories:\n"
            "- **RESEARCH**: For requests that require searching the web or finding recent information.\n"
            "- **CONVERSATION**: For simple conversational questions, greetings, or other general inquiries.\n"
            "- **EVALUATION**: If the user's response is 'yes' or 'no'.\n"
            "- **DASHBOARD**: If the user asks to see the security dashboard.\n"
            "- **MALICIOUS**: For requests that are clearly malicious, unethical, or harmful.\n"
            "- **CLARIFICATION**: If the user's request is ambiguous or you are unsure how to route it.\n\n"
            "Respond with only the category name (e.g., 'RESEARCH', 'CONVERSATION', 'EVALUATION', 'DASHBOARD', 'MALICIOUS', or 'CLARIFICATION')."
        )
        
        routing_request = LlmRequest(
            model=routing_model,
            contents=[
                types.Content(role='user', parts=[types.Part(text=routing_instruction)]),
                types.Content(role='model', parts=[types.Part(text="Okay, I understand. I will classify the user's request as either RESEARCH, CONVERSATION, EVALUATION, DASHBOARD, or CLARIFICATION.")]),
                types.Content(role='user', parts=[types.Part(text=user_input)])
            ]
        )

        # Get the routing decision from the LLM.
        routing_response = ""
        async for chunk in self.canonical_model.generate_content_async(routing_request):
            if chunk.content and chunk.content.parts:
                routing_response = chunk.content.parts[0].text
                break
        decision = routing_response.strip().upper()

        if self.verbose:
            yield self._create_log_event(f"🚦 [{self.name}] Routing decision: {decision}", author=self.name)

        # Route the request to the appropriate agent.
        if "RESEARCH" in decision:
            async for event in self._delegate_to("ResearcherAgent", ctx):
                yield event

        elif "EVALUATION" in decision:
            async for event in self._delegate_to("EvaluationAgent", ctx):
                yield event

        elif "DASHBOARD" in decision:
            async for event in self._delegate_to("SecurityDashboardAgent", ctx):
                yield event

        elif "MALICIOUS" in decision:
            yield Event(
                author=f"{self.name}|red|{self.icon}",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text="I cannot fulfill this request as it violates the security policy.")]
                )
            )

        elif "CLARIFICATION" in decision:
            if self.verbose:
                yield self._create_log_event(f"🤔 [{self.name}] Asking for clarification...", author=self.name)
            yield Event(
                author=f"{self.name}|{self.color}|{self.icon}",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text="I'm not sure how to handle your request. Could you please provide more details?")]
                )
            )

        else: # CONVERSATION
            if self.verbose:
                yield self._create_log_event(f"💬 [{self.name}] Handling conversation directly...", author=self.name)
            llm_request = LlmRequest(model=self.canonical_model.model, contents=[
                types.Content(role='user', parts=[types.Part(text=self.instruction)]),
                types.Content(role='model', parts=[types.Part(text="Okay, I understand. I will act as the orchestrator and respond to the user as such.")]),
                types.Content(role='user', parts=[types.Part(text=user_input)])
            ])
            response_text = ""
            async for chunk in self.canonical_model.generate_content_async(
                llm_request,
                stream=False
            ):
                if chunk.content and chunk.content.parts:
                    response_text += chunk.content.parts[0].text
            
            yield Event(
                author=f"{self.name}|{self.color}|{self.icon}",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=response_text)]
                )
            )



    async def _delegate_to(self, agent_name: str, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        """Delegate the request to the specified agent."""
        if self.verbose:
            yield self._create_log_event(f" delegating to '{agent_name}'...", author=self.name)
        agent = self._find_sub_agent(agent_name)
        if agent:
            async for event in agent.run_async(ctx):
                yield event
        else:
            yield self._create_log_event(f"Could not find '{agent_name}'.", author=self.name, color="red")

    def _find_sub_agent(self, agent_name: str) -> Optional[Agent]:
        """Find a sub-agent by name."""
        return next((agent for agent in self.sub_agents if agent.name == agent_name), None)