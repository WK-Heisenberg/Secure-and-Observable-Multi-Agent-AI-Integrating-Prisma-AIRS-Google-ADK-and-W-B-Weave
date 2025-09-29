#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

from enum import Enum
from typing import Optional


class ErrorType(Enum):
    """Enum defining error type codes for AISecSDK exceptions.

    These error types are used to categorize different errors that can occur
    within the SDK and are included in exception messages.
    """

    SERVER_SIDE_ERROR = "AISEC_SERVER_SIDE_ERROR"
    CLIENT_SIDE_ERROR = "AISEC_CLIENT_SIDE_ERROR"
    USER_REQUEST_PAYLOAD_ERROR = "AISEC_USER_REQUEST_PAYLOAD_ERROR"
    MISSING_VARIABLE = "AISEC_MISSING_VARIABLE"
    AISEC_SDK_ERROR = "AISEC_SDK_ERROR"


class AISecSDKException(Exception):
    """Base exception class for SDK-related exceptions."""

    def __init__(self, message: str = "", error_type: Optional[ErrorType] = None) -> None:
        self.message = message
        self.error_type = error_type

    def __str__(self) -> str:
        if self.error_type:
            return f"{self.error_type.value}:{self.message}"
        return f"{self.message}"
