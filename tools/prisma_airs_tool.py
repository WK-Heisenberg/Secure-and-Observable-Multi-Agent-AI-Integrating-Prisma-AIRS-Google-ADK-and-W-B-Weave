#!/usr/bin/env python3
"""
Prisma AIRS Security Tools for ADK Integration

This module provides ADK-compatible security scanning tools that use the
Prisma AIRS scanner directly.
"""
import logging
from typing import Dict, Any
from google.adk.tools import BaseTool

# Import the synchronous scanner instance.
# Assuming a synchronous scanner is available in prisma_airs_http.
from security.prisma_airs_http import security_scanner
PRISMA_AIRS_SCANNER_AVAILABLE = security_scanner.is_configured

# Configure logging
logger = logging.getLogger(__name__)

class PrismaAIRSLogic:
    """Contains the core logic for security scanning tools."""
    
    def __init__(self):
        self.scanner = security_scanner if PRISMA_AIRS_SCANNER_AVAILABLE else None
        
        if self.is_available:
            logger.info("🔒 Prisma AIRS security tools logic initialized (HTTP-only)")
        else:
            logger.error("🔒 Prisma AIRS scanner not available - security tools disabled")
            
    @property
    def is_available(self) -> bool:
        """Check if scanner is configured"""
        return self.scanner is not None and self.scanner.is_configured
    
    async def scan_prompt_security(self, prompt: str) -> Dict[str, Any]:
        """Asynchronously scans a prompt for security threats."""
        if self.is_available:
            try:
                result = await self.scanner.scan_content_async(prompt, "prompt")
                action = result.get("action", "block")
                return {
                    "action": action,
                    "category": result.get("category", "scan_error"),
                    "reason": result.get("reason", "Scan failed"),
                    "scan_id": result.get("scan_id", "ERROR"),
                    "is_safe": action == "allow",
                    "scan_duration_ms": result.get("scan_duration_ms", 0.0),
                    "scan_method": result.get("scan_method", "error")
                }
            except Exception as e:
                logger.error(f"Prisma AIRS scan failed: {str(e)}")
                err_res = self.scanner._create_error_response("prompt", str(e))
                return {**err_res, "is_safe": False}
        else:
            # No scanning method available - block for security
            return {
                "action": "block",
                "category": "no_scanner",
                "reason": "Prisma AIRS scanner not available - blocking for security",
                "scan_id": "NO_SCANNER",
                "is_safe": False,
                "scan_duration_ms": 0.0,
                "scan_method": "unavailable"
            }

# --- ADK Tool Definition ---

# Create a single instance of the logic class to be shared by tools
_prisma_airs_logic = PrismaAIRSLogic()

class ScanPromptSecurityTool(BaseTool):
    """An ADK tool that scans a given text prompt for security threats using Prisma AIRS."""

    def run(self, prompt: str) -> Dict[str, Any]:
        """
        Scans a text prompt for potential security risks like prompt injection,
        malicious content, or policy violations.

        Args:
            prompt: The text content to be scanned.

        Returns:
            A dictionary containing the scan result, including an 'action'
            ('allow' or 'block'), 'category' of threat, a 'reason', and
            whether the prompt 'is_safe'.
        """
        return _prisma_airs_logic.scan_prompt_security(prompt)

# --- Tool Instantiation and Export ---

# Create tool instances that can be imported and used by agents
scan_prompt_tool = ScanPromptSecurityTool()

# Export a list of all security tools for easy registration with an agent
SECURITY_TOOLS = [
    scan_prompt_tool,
]