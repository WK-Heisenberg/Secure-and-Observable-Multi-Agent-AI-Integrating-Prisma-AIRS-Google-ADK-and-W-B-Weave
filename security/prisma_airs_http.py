#!/usr/bin/env python3
"""
Asynchronous Prisma AIRS Security Scanner using aiohttp
"""
import os
import logging
import asyncio
import aiohttp
import ssl
import time
from typing import Dict, Any

# Setup logging
logger = logging.getLogger(__name__)

# Prisma AIRS API Configuration
AIRS_API_ENDPOINT_DEFAULT = "https://service.api.aisecurity.paloaltonetworks.com"
AIRS_API_VERSION = "v1"

class AsyncHTTPSecurityScanner:
    """Asynchronous security scanner for Prisma AIRS using aiohttp"""
    
    def __init__(self):
        self.api_key = os.environ.get("AIRS_API_KEY")
        self.profile_name = os.environ.get("AIRS_API_PROFILE_NAME")
        self.endpoint = os.environ.get("PRISMA_AIRS_ENDPOINT", AIRS_API_ENDPOINT_DEFAULT)
        self.timeout = int(os.environ.get("SECURITY_TIMEOUT_MS", 5000)) / 1000.0
        self.fail_open = os.environ.get("SECURITY_FAIL_OPEN", "false").lower() == "true"
        
        # Metrics
        self.scan_count = 0
        self.blocked_count = 0
        self.error_count = 0
        self.total_scan_time = 0.0
        
        # HTTP session
        self.is_configured = bool(self.api_key and self.profile_name)
        if self.is_configured:
            logger.info(f"✅ Async HTTP Prisma AIRS scanner initialized. Endpoint: {self.endpoint}")
            connector = aiohttp.TCPConnector(
                ssl=self._get_ssl_context(),
                limit_per_host=10
            )
            self.session = aiohttp.ClientSession(connector=connector)
        else:
            self.session = None
            logger.warning("⚠️ Prisma AIRS not configured (AIRS_API_KEY or AIRS_API_PROFILE_NAME missing). Security scanning is DISABLED.")

    def _get_ssl_context(self):
        corporate_ca = os.environ.get('CORPORATE_CA_BUNDLE')
        if corporate_ca and os.path.exists(corporate_ca):
            logger.info(f"🔒 Using corporate CA: {corporate_ca}")
            ssl_context = ssl.create_default_context(cafile=corporate_ca)
            return ssl_context
        elif os.environ.get('CORPORATE_SSL_DISABLE', 'false').lower() == 'true':
            logger.warning("⚠️ SSL verification disabled")
            return False
        return True

    async def close_session(self):
        if self.session and not self.session.closed:
            await self.session.close()
            logger.info("HTTP session closed.")

    async def scan_content(self, content: str, content_type: str = "prompt") -> Dict[str, Any]:
        """
        Scans content using the global async HTTP scanner instance.
        """
        return await self.scan_content_async(content, content_type)

    def _create_scan_request(self, content: str, content_type: str = "prompt") -> Dict[str, Any]:
        """Create a properly formatted scan request"""
        return {
            "metadata": {
                "ai_model": "ADK Agent",
                "app_name": "prisma-airs-multi-agent",
                "app_user": "adk-user"
            },
            "contents": [{
                content_type: content
            }],
            "tr_id": f"adk-http-scan-{content_type}-{int(time.time())}",
            "ai_profile": {
                "profile_name": self.profile_name
            }
        }

    async def scan_content_async(self, content: str, content_type: str = "prompt") -> Dict[str, Any]:
        """
        Asynchronous content scanning using aiohttp.
        """
        start_time = time.time()
        
        if not self.is_configured or not self.session:
            logger.warning("Prisma AIRS not configured, bypassing scan.")
            return self._create_error_response(content_type, "Scanner not configured", allow=True)

        try:
            payload = self._create_scan_request(content, content_type)
            scan_url = self.endpoint
            
            headers = {
                "Content-Type": "application/json",
                "x-pan-token": self.api_key,
                "User-Agent": "prisma-airs-aiohttp/1.0"
            }

            async with self.session.post(
                scan_url,
                json=payload,
                timeout=self.timeout,
                headers=headers
            ) as response:
                response.raise_for_status()
                result = await response.json()
                
            scan_duration = (time.time() - start_time) * 1000
            self.scan_count += 1
            self.total_scan_time += scan_duration
            
            action = result.get("action", "allow")
            if action == "block":
                self.blocked_count += 1
            
            logger.info(f"✅ HTTP scan completed: {action} ({scan_duration:.1f}ms)")
            
            return {
                "action": action,
                "category": result.get("category", "unknown"),
                "reason": result.get("reason", "Scanned successfully"),
                "scan_id": result.get("scan_id"),
                "report_id": result.get("report_id"),
                "profile_name": result.get("profile_name"),
                "scan_method": "http-async",
                "scan_duration_ms": scan_duration
            }

        except asyncio.TimeoutError:
            logger.error(f"HTTP scan failed: Timeout after {self.timeout}s")
            self.error_count += 1
            return self._create_error_response(content_type, "Scan timed out")
        except aiohttp.ClientError as e:
            logger.error(f"HTTP scan failed: {e}")
            self.error_count += 1
            return self._create_error_response(content_type, f"Scan API error: {e}")
        except Exception as e:
            logger.error(f"HTTP scan unexpected error: {e}")
            self.error_count += 1
            return self._create_error_response(content_type, f"Unexpected scan error: {e}")

    def _create_error_response(self, content_type: str, error_msg: str, allow: bool = False) -> Dict[str, Any]:
        """
        Create standardized error response with fail-safe behavior.
        """
        if allow:
            action = "allow"
            reason = f"{error_msg} - allowing due to override"
        elif self.fail_open:
            action = "allow"
            reason = f"{error_msg} - allowing due to FAIL_OPEN=true"
        elif content_type == "prompt":
            action = "block"
            reason = f"{error_msg} - blocked for safety (FAIL_OPEN=false)"
        else: # content_type == "response"
            action = "allow"
            reason = f"{error_msg} - allowing response (FAIL_OPEN=false)"

        return {
            "action": action,
            "category": "scan_error",
            "reason": reason,
            "scan_id": "ERROR",
            "scan_method": "error",
            "scan_duration_ms": 0.0
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive scanner metrics"""
        return {
            "total_scans": self.scan_count,
            "blocked_scans": self.blocked_count,
            "error_scans": self.error_count,
            "avg_scan_time_ms": (self.total_scan_time / self.scan_count) if self.scan_count > 0 else 0,
            "is_configured": self.is_configured,
            "scan_method": "http-async",
            "fail_open_policy": self.fail_open
        }

# Create a global instance
security_scanner = AsyncHTTPSecurityScanner()

async def scan_content(content: str, content_type: str = "prompt") -> Dict[str, Any]:
    """
    Scans content using the global async HTTP scanner instance.
    """
    return await security_scanner.scan_content_async(content, content_type)