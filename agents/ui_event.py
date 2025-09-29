#!/usr/bin/env python3
"""
Custom Event class for UI data
"""

from google.adk.events import Event
from pydantic import Field
from typing import Optional, Dict, Any

class UIEvent(Event):
    """
    Custom event class that includes UI data.
    """
    ui: Optional[Dict[str, Any]] = Field(default_factory=dict)
