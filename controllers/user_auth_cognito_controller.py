from fastapi import Request, Response, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from dependencies import get_db_session
from services.user_auth_cognito_service import (
    user_cognito_login,
    user_google_login,
    user_cognito_signup,
    forgot_password_cognito,
    reset_password_cognito,
    get_user_profile,
    get_all_users,
    verify_jwt_token
)
from schemas.models import (
    UserLoginRequest,
    UserGoogleLoginRequest,
    UserSignupRequest,
    ForgotPasswordRequest,
    CognitoResetPasswordRequest
)
import logging

logger = logging.getLogger(__name__)


async def user_cognito_login_controller(
    login_data: UserLoginRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """User login with Cognito authentication"""
    try:
        result = user_cognito_login(login_data, db)
        
        if result["success"]:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=result
            )
            
    except Exception as e:
        logger.error(f"Cognito login controller error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )


async def user_google_login_controller(
    login_data: UserGoogleLoginRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """User Google login endpoint"""
    try:
        result = user_google_login(login_data, db)
        
        if result["success"]:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=result
            )
            
    except Exception as e:
        logger.error(f"Google login controller error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )


async def user_cognito_signup_controller(
    signup_data: UserSignupRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """User signup with Cognito registration"""
    try:
        result = await user_cognito_signup(signup_data, db)
        
        if result["success"]:
            return JSONResponse(
                status_code=status.HTTP_201_CREATED,
                content=result
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=result
            )
            
    except Exception as e:
        logger.error(f"Cognito signup controller error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )


async def user_forgot_password_cognito_controller(
    forgot_data: ForgotPasswordRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """Forgot password endpoint with Cognito"""
    try:
        result = await forgot_password_cognito(forgot_data, db)
        
        if result["success"]:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=result
            )
            
    except Exception as e:
        logger.error(f"Forgot password controller error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )


async def user_reset_password_cognito_controller(
    reset_data: CognitoResetPasswordRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """Reset password endpoint with Cognito confirmation code"""
    try:
        result = await reset_password_cognito(reset_data, db)
        
        if result["success"]:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=result
            )
            
    except Exception as e:
        logger.error(f"Reset password controller error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )


async def get_user_profile_controller(
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """Get user profile endpoint (requires authentication)"""
    try:
        # Get authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "success": False,
                    "message": "Authorization header required"
                }
            )
        
        # Extract token
        token = auth_header.split(" ")[1]
        
        # Verify token
        payload = verify_jwt_token(token)
        if not payload:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "success": False,
                    "message": "Invalid or expired token"
                }
            )
        
        # Get user profile
        user_profile = get_user_profile(payload["user_id"], db)
        
        if user_profile:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "success": True,
                    "message": "Profile retrieved successfully",
                    "data": user_profile
                }
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "success": False,
                    "message": "User not found"
                }
            )
            
    except Exception as e:
        logger.error(f"Get profile controller error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )


async def get_all_users_controller(
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session),
    page: int = 1,
    per_page: int = 20,
    sort: str = None,
    name: str = None,
    ic_number: str = None,
    status: str = None
):
    """Get all users endpoint (requires authentication)"""
    try:
        # Get all users
        result = get_all_users(
            db=db,
            page=page,
            per_page=per_page,
            sort=sort,
            name=name,
            ic_number=ic_number,
            status=status
        )
        
        if result["success"]:
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "Users retrieved successfully",
                    "data": result
                }
            )
        else:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": result.get("message", "Failed to retrieve users"),
                    "data": result
                }
            )
            
    except Exception as e:
        logger.error(f"Get all users controller error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "Internal server error"
            }
        )

