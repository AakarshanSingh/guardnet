from typing import Any, Dict, List, Optional, Union
import json
from fastapi import status
from fastapi.responses import JSONResponse
from app.utils.api.json_encoder import CustomJSONEncoder


def success_response(
    data: Any = None,
    message: str = "Operation successful",
    status_code: int = status.HTTP_200_OK,
) -> JSONResponse:
    """
    Create a standardized success response.

    Args:
        data: The data to return in the response
        message: A success message
        status_code: HTTP status code (default: 200 OK)

    Returns:
        JSONResponse: Standardized success response
    """
    content = {
        "success": True,
        "message": message,
    }

    if data is not None:
        content["data"] = data

    # Use CustomJSONEncoder to handle UUID and datetime serialization
    json_content = json.dumps(content, cls=CustomJSONEncoder)
    return JSONResponse(
        status_code=status_code,
        content=json.loads(json_content),
    )


def error_response(
    message: str = "An error occurred",
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    errors: Optional[List[Dict[str, Any]]] = None,
) -> JSONResponse:
    """
    Create a standardized error response.

    Args:
        message: Error message
        status_code: HTTP status code (default: 500 Internal Server Error)
        errors: List of detailed error information

    Returns:
        JSONResponse: Standardized error response
    """
    content = {
        "success": False,
        "message": message,
    }

    if errors:
        content["errors"] = errors

    # Use CustomJSONEncoder to handle UUID and datetime serialization
    json_content = json.dumps(content, cls=CustomJSONEncoder)
    return JSONResponse(
        status_code=status_code,
        content=json.loads(json_content),
    )


def validation_error_response(
    errors: List[Dict[str, Any]],
    message: str = "Validation error",
) -> JSONResponse:
    """
    Create a standardized validation error response.

    Args:
        errors: List of validation errors
        message: Error message

    Returns:
        JSONResponse: Standardized validation error response
    """
    return error_response(
        message=message,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        errors=errors,
    )


def not_found_response(
    resource_type: str = "Resource",
    message: Optional[str] = None,
) -> JSONResponse:
    """
    Create a standardized not found error response.

    Args:
        resource_type: Type of resource that was not found
        message: Custom message (optional)

    Returns:
        JSONResponse: Standardized not found response
    """
    if message is None:
        message = f"{resource_type} not found"

    return error_response(
        message=message,
        status_code=status.HTTP_404_NOT_FOUND,
    )


def unauthorized_response(
    message: str = "Unauthorized access",
) -> JSONResponse:
    """
    Create a standardized unauthorized error response.

    Args:
        message: Error message

    Returns:
        JSONResponse: Standardized unauthorized response
    """
    return error_response(
        message=message,
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
