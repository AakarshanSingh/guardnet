from datetime import timedelta
from typing import Any, Dict
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.auth import deps, schemas, utils
from app.core.config import settings
from app.database.base import get_db
from app.models.user import User
from app.utils.api.responses import (
    success_response,
    error_response,
    unauthorized_response,
)

router = APIRouter()


@router.post("/signup", response_model=None)
def create_user(
    request: Request,
    *,
    db: Session = Depends(get_db),
    user_in: schemas.UserCreate,
) -> Any:
    """
    Create a new user.
    """
    try:
        # Check if user with this email already exists
        user = db.query(User).filter(User.email == user_in.email).first()
        if user:
            return error_response(
                message="Email already registered",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Create new user with UUID
        user = User(
            name=user_in.name,
            email=user_in.email,
            password_hash=utils.get_password_hash(user_in.password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Create a serializable user object
        user_data = {
            "id": str(user.id),  # Convert UUID to string
            "name": user.name,
            "email": user.email,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }

        # Generate access token for immediate login after registration
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "access_token": utils.create_access_token(
                str(user.id), expires_delta=access_token_expires
            ),
            "token_type": "bearer",
            "user": user_data,
        }

        return success_response(
            data=token_data,
            message="User created successfully",
            status_code=status.HTTP_201_CREATED,
        )

    except SQLAlchemyError as e:
        db.rollback()
        return error_response(
            message=f"Database error: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception as e:
        db.rollback()
        return error_response(
            message=f"Error creating user: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/login", response_model=None)
def login(
    request: Request,
    db: Session = Depends(get_db),
    user_data: schemas.UserLogin = Body(...),
) -> Dict[str, Any]:
    """
    Login endpoint that accepts JSON data with email and password.
    Returns an access token for future requests.
    """
    try:
        # Extract email and password from JSON data
        email = user_data.email
        password = user_data.password

        # Authenticate user
        user = db.query(User).filter(User.email == email).first()
        if not user or not utils.verify_password(password, user.password_hash):
            return unauthorized_response(message="Incorrect email or password")

        # Create serializable user data
        user_data = {
            "id": str(user.id),  # Convert UUID to string
            "name": user.name,
            "email": user.email,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }

        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "access_token": utils.create_access_token(
                str(user.id), expires_delta=access_token_expires
            ),
            "token_type": "bearer",
            "user": user_data,
        }

        return success_response(
            data=token_data,
            message="Login successful",
            status_code=status.HTTP_200_OK,
        )

    except SQLAlchemyError as e:
        return error_response(
            message=f"Database error: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception as e:
        return error_response(
            message=f"Error during login: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/me", response_model=None)
def get_current_user(
    request: Request,
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Get current user information.
    """
    try:
        # Create serializable user data
        user_data = {
            "id": str(current_user.id),
            "name": current_user.name,
            "email": current_user.email,
            "created_at": (
                current_user.created_at.isoformat() if current_user.created_at else None
            ),
        }

        return success_response(
            data=user_data,
            message="User profile retrieved successfully",
        )
    except Exception as e:
        return error_response(
            message=f"Error retrieving user data: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/logout", response_model=None)
def logout(
    request: Request,
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Logout user.
    """
    # Note: For JWT tokens, actual logout is handled client-side by removing the token
    return success_response(message="Successfully logged out")


@router.post("/change-password", response_model=None)
def change_password(
    request: Request,
    *,
    db: Session = Depends(get_db),
    password_data: schemas.ChangePassword,
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Change user password.
    """
    try:
        # Verify current password
        if not utils.verify_password(
            password_data.current_password, current_user.password_hash
        ):
            return error_response(
                message="Incorrect current password",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Update password
        current_user.password_hash = utils.get_password_hash(password_data.new_password)
        db.add(current_user)
        db.commit()
        db.refresh(current_user)

        # Create serializable user data
        user_data = {
            "id": str(current_user.id),
            "name": current_user.name,
            "email": current_user.email,
            "created_at": (
                current_user.created_at.isoformat() if current_user.created_at else None
            ),
        }

        # Generate new access token after password change
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "access_token": utils.create_access_token(
                str(current_user.id), expires_delta=access_token_expires
            ),
            "token_type": "bearer",
            "user": user_data,
        }

        return success_response(
            data=token_data,
            message="Password changed successfully",
        )

    except SQLAlchemyError as e:
        db.rollback()
        return error_response(
            message=f"Database error: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception as e:
        db.rollback()
        return error_response(
            message=f"Error changing password: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.post("/validate-token", response_model=None)
def validate_token(
    request: Request,
    current_user: User = Depends(deps.get_current_active_user),
) -> Dict[str, Any]:
    """
    Validate JWT token and return basic user info.
    Useful for frontend to check if token is still valid.
    """
    try:
        # Create serializable user data
        user_data = {
            "id": str(current_user.id),
            "name": current_user.name,
            "email": current_user.email,
            "created_at": (
                current_user.created_at.isoformat() if current_user.created_at else None
            ),
        }

        # Return the serialized user object along with token validity
        token_data = {
            "valid": True,
            "user": user_data,
        }

        return success_response(
            data=token_data,
            message="Token is valid",
        )
    except Exception as e:
        return error_response(
            message=str(e),
            status_code=status.HTTP_401_UNAUTHORIZED,
            errors=[{"detail": "Invalid token"}],
        )
