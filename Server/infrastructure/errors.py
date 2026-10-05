from enum import Enum


class ErrorType(str, Enum):
    UNKNOWN_SERVICE = "UnknownService"
    VALIDATION_ERROR = "ValidationError"
    TIMEOUT_ERROR = "TimeOutError"
    INTERNAL_ERROR = "InternalError"
    NOT_FOUND_ERROR = "NotFoundError"
    AUTH_ERROR = "AuthError"
    UPSTREAM_SERVICE_ERROR = "UpstreamServiceError"
