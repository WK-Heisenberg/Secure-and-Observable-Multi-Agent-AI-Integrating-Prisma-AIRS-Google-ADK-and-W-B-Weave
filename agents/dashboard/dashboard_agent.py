#!/usr/bin/env python3
"""
Security Dashboard Agent
"""
import logging
import datetime
from typing import AsyncGenerator

from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.genai import types

from agents.secure_base_agent import SecureBaseAgent

# Configure logging
logger = logging.getLogger(__name__)

class SecurityDashboardAgent(SecureBaseAgent):
    """
    An agent that displays the security events.
    """

    def __init__(self, name: str = "SecurityDashboardAgent", color: str = "orange", icon: str = "security", verbose: bool = False):
        super().__init__(
            name=name,
            color=color,
            icon=icon,
            verbose=verbose,
            model="gemini-2.5-flash-lite",
            instruction="You are a security dashboard agent. Your job is to display the security events."
        )
        logger.info(f"Initialized {name}.")

    async def _secure_agent_logic(
        self, ctx: InvocationContext, user_input: str
    ) -> AsyncGenerator[Event, None]:
        """
        Displays the security events.
        """
        security_events = self.get_security_events()
        if security_events:
            response_text = "### Security Events\n\n"
            for event in sorted(security_events, key=lambda x: x['timestamp'], reverse=True):
                ts = datetime.datetime.fromtimestamp(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                response_text += f"- **Timestamp:** {ts}\n"
                response_text += f"- **Agent:** {event['agent']}\n"
                response_text += f"- **Event Type:** {event['event_type']}\n"
                response_text += f"- **Action:** {event['action']}\n"
                response_text += f"- **Category:** {event['category']}\n"
                response_text += f"- **Scan ID:** {event['scan_id']}\n"
                response_text += f"- **Content Preview:** {event['content_preview']}\n"
                response_text += f"- **Blocked:** {event['blocked']}\n"
                response_text += "---\n"
        else:
            response_text = "No security events to display."

        yield Event(
            author=f"{self.name}|{self.color}|{self.icon}",
            content=types.Content(
                role="model",
                parts=[types.Part(text=response_text)]
            )
        )
