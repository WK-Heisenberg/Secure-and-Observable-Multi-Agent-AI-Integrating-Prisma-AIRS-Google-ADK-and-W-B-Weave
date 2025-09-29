#!/usr/bin/env python3
"""
Evaluation Agent
"""
import logging
from typing import AsyncGenerator

from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.genai import types

from agents.secure_base_agent import SecureBaseAgent

# Configure logging
logger = logging.getLogger(__name__)

class EvaluationAgent(SecureBaseAgent):
    """
    An agent that asks the user for feedback on the previous response.
    """

    def __init__(self, name: str = "EvaluationAgent", color: str = "purple", icon: str = "thumb_up_off_alt", verbose: bool = False):
        super().__init__(
            name=name,
            color=color,
            icon=icon,
            verbose=verbose,
            model="gemini-2.5-flash-lite",
            instruction="You are an evaluation agent. Your job is to ask the user for feedback on the previous response."
        )
        logger.info(f"Initialized {name}.")

    async def _secure_agent_logic(
        self, ctx: InvocationContext, user_input: str
    ) -> AsyncGenerator[Event, None]:
        """
        Asks the user for feedback.
        """
        session_id = ctx.session.id if hasattr(ctx, "session") and hasattr(ctx.session, "id") else "unknown"
        feedback = user_input.lower()
        if feedback in ["yes", "no"]:
            self._log_feedback_to_wandb(session_id, feedback)
            yield Event(
                author=f"{self.name}|{self.color}|{self.icon}",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text="Thank you for your feedback!")]
                )
            )
        else:
            yield Event(
                author=f"{self.name}|{self.color}|{self.icon}",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text="I didn't understand your feedback. Please respond with 'yes' or 'no'.")]
                )
            )
