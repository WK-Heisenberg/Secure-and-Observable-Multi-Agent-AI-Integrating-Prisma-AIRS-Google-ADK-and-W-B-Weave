#!/usr/bin/env python3
"""
Custom Google Search Tool with Weave Tracing
"""
import weave
from google.adk.tools import google_search
from google.adk.tools.base_tool import BaseTool

class TracedGoogleSearchTool(BaseTool):
    """A wrapper around the built-in Google Search tool that adds Weave tracing."""

    def __init__(self):
        super().__init__(
            name="google_search",
            description="A tool for searching the web."
        )

    @weave.op()
    async def __call__(self, query: str) -> str:
        """Executes a Google search and returns the results."""
        return await google_search(query)

traced_google_search = TracedGoogleSearchTool()
