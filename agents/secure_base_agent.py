#!/usr/bin/env python3
"""
Secure Base Agent for ADK Integration

This base agent class integrates Prisma AIRS security scanning into all LLM interactions.
All specialized agents MUST inherit from this class.
"""
import logging
import time
import os
import weave
import wandb
from typing import AsyncGenerator, Dict, Any, Optional, List
from abc import ABC, abstractmethod

# ADK imports
from google.adk.agents import LlmAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.genai import types

# Import our security middleware
from security.security_middleware import security_middleware, SecurityScanResult

# Configure logging
logger = logging.getLogger(__name__)

class SecureBaseAgent(LlmAgent, ABC):
    """
    Base agent class that provides automatic Prisma AIRS security scanning
    for all LLM interactions.
    """
    
    class Config:
        extra = "allow"  # Allow dynamic attributes
    
    security_events: List[Dict[str, Any]] = []

    def __init__(self, name: str, color: str = "grey", icon: str = "robot_2", verbose: bool = False, **kwargs):
        # Ensure model is passed to LlmAgent
        if "model" not in kwargs:
            kwargs["model"] = os.environ.get("VERTEX_AI_MODEL", "gemini-2.5-flash")
            
        super().__init__(name=name, **kwargs)
        self.color = color
        self.icon = icon
        self.verbose = verbose
        self.security_middleware = security_middleware
        # W&B Table for logging conversations
        self.wandb_table = wandb.Table(columns=["session_id", "user_input", "agent_response", "prompt_scan_result", "response_scan_result", "timestamp"])
        # W&B Table for logging user feedback
        self.feedback_table = wandb.Table(columns=["session_id", "feedback", "timestamp"])
        
        logger.info(f"🔒 Initialized secure agent: {name} with Prisma AIRS protection")
    
    @weave.op()
    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        """
        Secure implementation that wraps agent logic with security scanning.
        
        This method:
        1. Extracts and scans the user prompt
        2. Calls the agent's secure business logic
        3. Scans all responses before yielding them
        4. Blocks any content that Prisma AIRS flags
        """
        
        user_input = self._extract_user_input(ctx)
        agent_context = {
            "agent_name": self.name,
            "session_id": ctx.session.id if hasattr(ctx, "session") and hasattr(ctx.session, "id") else "unknown",
        }
        
        with weave.attributes({"user_input": user_input}):
            if self.verbose:
                yield self._create_log_event(f"🕵️ [{self.name}] Analyzing user prompt...", author=self.name, color="grey")
            
            # 🔒 STEP 1: Scan user prompt before processing
            prompt_scan_result = await self.security_middleware.scan_prompt(
                user_input,  
                context=agent_context
            )
            
            self._record_security_event("prompt_scan", prompt_scan_result, user_input[:100])
            
            # Block if prompt is malicious
            if prompt_scan_result.is_blocked:
                logger.warning(f"[{self.name}] 🚨 Input blocked by Prisma AIRS")
                yield self._create_log_event(f"🚨 [{self.name}] Input blocked by Prisma AIRS. Reason: {prompt_scan_result.category}", author="Prisma AIRS", color="red", icon="security")
                security_message = self.security_middleware.create_security_block_message(
                    prompt_scan_result, "prompt"
                )
                yield Event(
                    content=types.Content(
                        role="model",
                        parts=[types.Part(text=security_message)]
                    ),
                    author=f"{self.name}|red|{self.icon}"
                )
                return
            
            if self.verbose:
                yield self._create_log_event(f"✅ [{self.name}] Input approved by Prisma AIRS.", author="Prisma AIRS", color="green", icon="security")
            
            # 🔒 STEP 2: Execute secure agent logic
            try:
                response_text = ""
                async for event in self._secure_agent_logic(ctx, user_input):
                    if event.content and event.content.parts:
                        response_text += event.content.parts[0].text

                with weave.attributes({"agent_response": response_text}):
                    # 🔒 STEP 3: Scan the complete agent response
                    response_scan_result, response_text = await self.security_middleware.scan_response(
                        response_text, context=agent_context
                    )
                    self._record_security_event("response_scan", response_scan_result, response_text[:100])

                    if response_scan_result.is_blocked:
                        logger.warning(f"[{self.name}] 🚨 Response blocked by Prisma AIRS")
                        yield self._create_log_event(f"🚨 [{self.name}] Response blocked by Prisma AIRS. Reason: {response_scan_result.category}", author="Prisma AIRS", color="red", icon="security")
                        security_message = self.security_middleware.create_security_block_message(
                            response_scan_result, "response"
                        )
                        yield Event(
                            content=types.Content(
                                role="model",
                                parts=[types.Part(text=security_message)]
                            ),
                            author=f"{self.name}|red|{self.icon}"
                        )
                    else:
                        if self.verbose:
                            yield self._create_log_event(f"✅ [{self.name}] Response approved by Prisma AIRS. Scan ID: {response_scan_result.scan_id}", author="Prisma AIRS", color="green", icon="security")
                        yield Event(
                            author=f"{self.name}|{self.color}|{self.icon}",
                            content=types.Content(
                                role="model",
                                parts=[types.Part(text=response_text)]
                            )
                        )

                    self._log_conversation_to_wandb(
                        agent_context["session_id"],
                        user_input,
                        response_text,
                        prompt_scan_result,
                        response_scan_result
                    )

            except Exception as e:
                logger.error(f"[{self.name}] Error in secure agent logic: {e}", exc_info=True)
                yield Event(
                    content=types.Content(
                        role="model",
                        parts=[types.Part(text=f"❌ Agent error: {e}")]
                    ),
                    author=f"{self.name}|red|{self.icon}"
                )

    def _log_conversation_to_wandb(self, session_id, user_input, agent_response, prompt_scan_result, response_scan_result):
        """Log the conversation to a W&B Table."""
        self.wandb_table.add_data(
            session_id,
            user_input,
            agent_response,
            vars(prompt_scan_result),
            vars(response_scan_result),
            time.time()
        )

    def _log_feedback_to_wandb(self, session_id, feedback):
        """Log the user feedback to a W&B Table."""
        self.feedback_table.add_data(
            session_id,
            feedback,
            time.time()
        )

    def get_security_events(self) -> List[Dict[str, Any]]:
        """Return the security events."""
        return self.security_events

    @abstractmethod
    async def _secure_agent_logic(
        self, ctx: InvocationContext, user_input: str
    ) -> AsyncGenerator[Event, None]:
        """
        Agent-specific logic.
        
        Subclasses MUST implement this method instead of _run_async_impl.
        The `user_input` is the already-scanned and approved prompt.
        All events yielded from this method will be automatically scanned.
        """
        # Example: yield Event(content=...)
        pass
    
    def _extract_user_input(self, ctx: InvocationContext) -> str:
        """Extract user input text from invocation context"""
        try:
            if ctx.user_content and ctx.user_content.parts:
                return ctx.user_content.parts[0].text or ""
            return "No input provided"
        except Exception as e:
            logger.error(f"Error extracting user input: {e}", exc_info=True)
            return "Error extracting input"
    
    def _record_security_event(self, event_type: str, scan_result: SecurityScanResult, content_preview: str):
        """Record security events for audit trail"""
        security_event = {
            "timestamp": time.time(),
            "agent": self.name,
            "event_type": event_type,
            "action": scan_result.action,
            "category": scan_result.category,
            "scan_id": scan_result.scan_id,
            "content_preview": content_preview,
            "blocked": scan_result.is_blocked
        }
        self.security_events.append(security_event)
        if len(self.security_events) > 50:
            self.security_events = self.security_events[-50:]

    def _create_log_event(self, message: str, author: str, color: Optional[str] = None, icon: Optional[str] = None) -> Event:
        """Create a new log event to be sent to the UI"""
        log_color = color if color is not None else self.color
        log_icon = icon if icon is not None else self.icon
        return Event(
            author=f"{author}|{log_color}|{log_icon}",
            content=types.Content(
                role="model",
                parts=[types.Part(text=message)]
            )
        )
