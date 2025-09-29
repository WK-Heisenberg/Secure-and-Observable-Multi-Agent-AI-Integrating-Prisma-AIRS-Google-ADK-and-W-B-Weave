#!/usr/bin/env python3
"""
Prisma AIRS Security Middleware for ADK Agents
"""
import logging
import time
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

# Import the corrected async scanner instance
from security.prisma_airs_http import scan_content, security_scanner

# Import W&B for metrics logging
try:
    import wandb
    WANDB_AVAILABLE = True
except ImportError:
    WANDB_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class SecurityScanResult:
    """Result of a security scan"""
    action: str  # "allow" or "block"  
    category: str  # "benign", "malicious", etc.
    reason: str
    scan_id: Optional[str] = None
    scan_duration_ms: float = 0.0
    scan_method: str = "none"
    redacted: bool = False
        
    @property
    def is_allowed(self) -> bool:
        return self.action == "allow"
        
    @property
    def is_blocked(self) -> bool:
        return self.action == "block"

class PrismaAIRSSecurityMiddleware:
    """
    Security middleware that scans all agent communications.
    """
    
    def __init__(self):
        self.scan_count = 0
        self.blocked_count = 0
        self.total_scan_time = 0.0
        self.scan_history: List[Dict[str, Any]] = []
        
        # Check if scanner is properly configured
        self.scanner_available = security_scanner.is_configured
        
        if self.scanner_available:
            logger.info("✅ Prisma AIRS security middleware initialized (HTTP-async)")
        else:
            logger.warning("⚠️ Prisma AIRS scanner not configured - security scanning is DISABLED")
    
    async def scan_prompt(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> SecurityScanResult:
        """Scan a prompt before sending to LLM."""
        start_time = time.time()
        self.scan_count += 1
        
        if not self.scanner_available:
            return SecurityScanResult(
                action="allow",
                category="no_scan",
                reason="Prisma AIRS scanner not configured - bypassing scan",
                scan_method="none"
            )
        
        try:
            logger.info(f"🔍 Scanning prompt via Prisma AIRS: {prompt[:50]}...")
            
            scan_result = await scan_content(prompt, "prompt")
            
            scan_duration = (time.time() - start_time) * 1000
            self.total_scan_time += scan_duration
            
            result = SecurityScanResult(
                action=scan_result.get("action", "block"),
                category=scan_result.get("category", "unknown"),
                reason=scan_result.get("reason", "Scanned by Prisma AIRS"),
                scan_id=scan_result.get("scan_id"),
                scan_duration_ms=scan_result.get("scan_duration_ms", scan_duration),
                scan_method=scan_result.get("scan_method", "http-async")
            )
            
            if result.is_blocked:
                self.blocked_count += 1
                logger.warning(f"🚨 PROMPT BLOCKED by Prisma AIRS: {result.reason}")
            else:
                logger.info(f"✅ Prompt approved by Prisma AIRS (Scan ID: {result.scan_id})")
            
            self._record_scan("prompt", prompt[:100], result, context)
            return result
            
        except Exception as e:
            scan_duration = (time.time() - start_time) * 1000
            logger.error(f"❌ Prompt scan failed: {str(e)}")
            
            err_res = security_scanner._create_error_response("prompt", f"Middleware scan failed: {e}")
            return SecurityScanResult(
                action=err_res["action"],
                category=err_res["category"],
                reason=err_res["reason"],
                scan_duration_ms=scan_duration,
                scan_method="error"
            )
    
    async def scan_response(self, response: str, context: Optional[Dict[str, Any]] = None) -> SecurityScanResult:
        """Scan a response from LLM before returning to user."""
        start_time = time.time()
        self.scan_count += 1
        
        if not self.scanner_available:
            return SecurityScanResult(
                action="allow",
                category="no_scan",
                reason="Prisma AIRS scanner not configured - bypassing scan",
                scan_method="none"
            )
        
        try:
            logger.info(f"🔍 Scanning response via Prisma AIRS: {response[:50]}...")
            
            scan_result = await scan_content(response, "response")
            
            scan_duration = (time.time() - start_time) * 1000
            self.total_scan_time += scan_duration
            
            result = SecurityScanResult(
                action=scan_result.get("action", "allow"),
                category=scan_result.get("category", "unknown"),
                reason=scan_result.get("reason", "Scanned by Prisma AIRS"),
                scan_id=scan_result.get("scan_id"),
                scan_duration_ms=scan_result.get("scan_duration_ms", scan_duration),
                scan_method=scan_result.get("scan_method", "http-async")
            )
            
            if result.is_blocked:
                self.blocked_count += 1
                logger.warning(f"🚨 RESPONSE BLOCKED by Prisma AIRS: {result.reason}")
            else:
                logger.info(f"✅ Response approved by Prisma AIRS (Scan ID: {result.scan_id})")
                response, redacted = self.redact_sensitive_data(response)
                result.redacted = redacted

            self._record_scan("response", response[:100], result, context)
            return result, response
            
        except Exception as e:
            scan_duration = (time.time() - start_time) * 1000
            logger.error(f"❌ Response scan failed: {str(e)}")
            
            err_res = security_scanner._create_error_response("response", f"Middleware scan failed: {e}")
            return SecurityScanResult(
                action=err_res["action"],
                category=err_res["category"],
                reason=err_res["reason"],
                scan_duration_ms=scan_duration,
                scan_method="error"
            ), response

    def redact_sensitive_data(self, text: str) -> (str, bool):
        """Redact sensitive data from text."""
        redacted = False
        # Redact email addresses
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        if re.search(email_pattern, text):
            text = re.sub(email_pattern, "[REDACTED]", text)
            redacted = True

        # Redact phone numbers (more specific regex)
        phone_pattern = r"(?:\b|\D)(\d{3}[-.]?\d{3}[-.]?\d{4})(?:\b|\D)"
        matches = list(re.finditer(phone_pattern, text))
        if matches:
            redacted = True
            # Iterate backwards to not mess up indices
            for match in reversed(matches):
                start, end = match.span(1)
                text = text[:start] + "[REDACTED]" + text[end:]
            
        return text, redacted

    def create_security_block_message(self, scan_result: SecurityScanResult, content_type: str = "content") -> str:
        """Create a user-friendly message when content is blocked."""
        return f"""🛡️ **Security Notice**

Your {content_type} has been blocked by Prisma AIRS security scanning.

**Reason:** {scan_result.reason}
**Category:** {scan_result.category}
**Scan ID:** {scan_result.scan_id or 'N/A'}

Please review your content and try again."""
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics for monitoring."""
        avg_scan_time = (
            self.total_scan_time / self.scan_count 
            if self.scan_count > 0 else 0
        )
        
        scanner_metrics = security_scanner.get_metrics()
        
        return {
            "middleware_total_scans": self.scan_count,
            "middleware_blocked_scans": self.blocked_count,
            "middleware_block_rate_percent": (self.blocked_count / self.scan_count * 100) if self.scan_count > 0 else 0,
            "middleware_average_scan_time_ms": round(avg_scan_time, 2),
            "scanner_available": self.scanner_available,
            "scanner_metrics": scanner_metrics
        }
    
    def _record_scan(self, scan_type: str, content_preview: str, result: SecurityScanResult, context: Optional[Dict[str, Any]]):
        """Record scan in history and log to W&B"""
        scan_record = {
            "timestamp": time.time(),
            "scan_type": scan_type,
            "content_preview": content_preview,
            "action": result.action,
            "category": result.category,
            "reason": result.reason,
            "scan_id": result.scan_id,
            "duration_ms": result.scan_duration_ms,
            "scan_method": result.scan_method,
            "redacted": result.redacted,
            "context": context or {}
        }
        
        self.scan_history.append(scan_record)
        
        if len(self.scan_history) > 100:
            self.scan_history = self.scan_history[-100:]
        
        if WANDB_AVAILABLE and wandb.run:
            try:
                metrics = {
                    f"security/{scan_type}_scan_latency": result.scan_duration_ms,
                    f"security/{scan_type}_action_{result.action}": 1,
                    f"security/category_{result.category}": 1,
                    "security/total_scans": self.scan_count,
                    "security/blocked_scans": self.blocked_count,
                }
                if result.redacted:
                    metrics["security/redacted_responses"] = 1
                wandb.log(metrics)
            except Exception as e:
                logger.debug(f"W&B logging failed: {str(e)}")

# Create global security middleware instance
security_middleware = PrismaAIRSSecurityMiddleware()