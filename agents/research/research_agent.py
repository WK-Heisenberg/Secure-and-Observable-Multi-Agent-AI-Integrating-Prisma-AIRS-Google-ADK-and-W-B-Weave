#!/usr/bin/env python3
"""
Secure Research Agent with Prisma AIRS Integration and Google Search Tool.
"""
import logging
from typing import AsyncGenerator

from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.adk.models.llm_request import LlmRequest
from google.genai import types
from google.api_core import exceptions as google_exceptions

# Import the secure base class and the new tool
from agents.secure_base_agent import SecureBaseAgent
from tools.google_search_tool import traced_google_search

# Configure logging
logger = logging.getLogger(__name__)

class ResearcherAgent(SecureBaseAgent):
    """
    A specialized agent for conducting web research.

    This agent inherits from SecureBaseAgent, ensuring all its inputs and
    outputs are automatically scanned by Prisma AIRS. It is equipped with
    the GoogleSearchTool to find real-time information and synthesize it
    into a comprehensive answer.
    """

    def __init__(self, name: str = "ResearcherAgent", color: str = "green", icon: str = "travel_explore", verbose: bool = False):
        super().__init__(
            name=name,
            color=color,
            icon=icon,
            verbose=verbose,
            model="gemini-2.5-flash",
            instruction=(
                "You are a specialized research agent. Your sole purpose is to answer "
                "user queries by using the GoogleSearchTool. You must use the tool to find "
                "relevant information and then synthesize the findings into a concise summary of the top 3-5 key points. "
                "Format your response using markdown, including headings, bullet points, and bold text to improve readability. "
                "Cite your sources by including the URL at the end of relevant sentences. "
                "Do not answer from your own knowledge. If the tool fails or returns no results, "
                "state that you were unable to find information on the topic."
            ),
            tools=[traced_google_search]  # Equip the agent with the search tool [4]
        )
        logger.info(f"Initialized {name} with security scanning and Google Search tool.")

    async def _secure_agent_logic(
        self, ctx: InvocationContext, user_input: str
    ) -> AsyncGenerator[Event, None]:
        """
        Executes the research workflow.

        The 'user_input' has already been scanned and approved by the security
        middleware. This method leverages the LLM's function-calling ability
        to use the provided GoogleSearchTool. All yielded events will be
        scanned before being sent.
        """
        if self.verbose:
            yield self._create_log_event(f"🔎 [{self.name}] Starting research for: '{user_input[:30]}...'", author=self.name)

        try:
            llm_request = LlmRequest(model=self.canonical_model.model, contents=[types.Content(role='user', parts=[types.Part(text=user_input)])])
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
        except google_exceptions.GoogleAPICallError as e:
            logger.error(f"[{self.name}] Google API error during research: {e}", exc_info=True)
            yield self._create_log_event(
                f"🔎 [{self.name}] I am sorry, but I encountered an error while communicating with the Google API. Please try again later.",
                author=self.name,
                color="red"
            )
        except Exception as e:
            logger.error(f"[{self.name}] Error during research: {e}", exc_info=True)
            yield self._create_log_event(
                f"🔎 [{self.name}] I am sorry, but I encountered an unexpected error while trying to research your query. Please try again later.",
                author=self.name,
                color="red"
            )