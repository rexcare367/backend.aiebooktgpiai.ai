from fastapi import APIRouter, Request, Response, Depends, status, Query
from controllers.user_auth_cognito_controller import (
    user_cognito_login_controller,
    user_google_login_controller,
    user_cognito_signup_controller,
    user_forgot_password_cognito_controller,
    user_reset_password_cognito_controller,
    get_user_profile_controller,
    get_all_users_controller
)
from schemas.models import (
    UserLoginRequest,
    UserGoogleLoginRequest,
    UserSignupRequest,
    ForgotPasswordRequest,
    CognitoResetPasswordRequest
)
from dependencies import get_db_session
from sqlalchemy.orm import Session

router = APIRouter(
    prefix="/api/user/auth/cognito",
    tags=["user-auth-cognito"],
)

@router.post("/login", status_code=status.HTTP_200_OK)
async def cognito_login(
    login_data: UserLoginRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """
    User login endpoint with AWS Cognito authentication
    
    Accepts:
    - identifier: email or ic_number
    - password: user password
    
    Returns:
    - Cognito tokens (id_token, access_token, refresh_token)
    - Custom JWT token for backward compatibility
    - User information
    
    Process:
    1. Validates user exists in database
    2. Checks user is active
    3. Authenticates with AWS Cognito
    4. Returns tokens and user data
    """
    return await user_cognito_login_controller(login_data, response, db)


@router.post("/google-login", status_code=status.HTTP_200_OK)
async def google_login(
    login_data: UserGoogleLoginRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """
    User Google OAuth login endpoint
    
    Accepts:
    - email: user email from Google
    
    Returns:
    - JWT token for authentication
    - User information
    """
    return await user_google_login_controller(login_data, response, db)


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def cognito_signup(
    signup_data: UserSignupRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """
    User signup endpoint with AWS Cognito registration
    
    Required fields:
    - email: user email
    - phone: user phone number
    - password: user password (min 8 characters)
    - ic_number: user IC number (must exist in system)
    
    Business logic:
    1. Validates IC number exists in database
    2. Checks IC number hasn't been registered yet
    3. Validates email is unique
    4. Creates user in AWS Cognito
    5. Auto-confirms user (bypasses email verification)
    6. Updates database with user information
    7. Sends welcome email
    
    Returns:
    - Cognito user ID
    - Custom JWT token
    - User information
    """
    return await user_cognito_signup_controller(signup_data, response, db)


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def cognito_forgot_password(
    forgot_data: ForgotPasswordRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """
    Forgot password endpoint with AWS Cognito
    
    Accepts:
    - email: user email
    
    Process:
    1. Validates user exists and is active in database
    2. Initiates Cognito forgot password flow
    3. Cognito sends confirmation code to user's email
    
    Note: 
    - User will receive a verification code via email
    - Use /reset-password endpoint with the code to complete password reset
    """
    return await user_forgot_password_cognito_controller(forgot_data, response, db)


@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def cognito_reset_password(
    reset_data: CognitoResetPasswordRequest,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """
    Reset password endpoint with AWS Cognito confirmation code
    
    Required fields:
    - email: user email
    - confirmation_code: code received via email from forgot-password
    - new_password: new password (min 8 characters)
    
    Process:
    1. Validates user exists in database
    2. Confirms password reset with Cognito using confirmation code
    3. Updates database timestamp
    4. Sends confirmation email
    """
    return await user_reset_password_cognito_controller(reset_data, response, db)


@router.get("/profile", status_code=status.HTTP_200_OK)
async def get_profile(
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session)
):
    """
    Get user profile endpoint
    
    Requires:
    - Authorization header with Bearer token (custom JWT token)
    
    Returns:
    - User profile information
    """
    return await get_user_profile_controller(request, response, db)


@router.get("/users", status_code=status.HTTP_200_OK)
async def get_all_users(
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session),
    page: int = Query(1, ge=1, description="Page number for pagination"),
    per_page: int = Query(20, ge=1, le=100, description="Number of users per page"),
    sort: str = Query(None, description="Sort criteria in JSON format"),
    name: str = Query(None, description="Filter by user name (partial match)"),
    ic_number: str = Query(None, description="Filter by IC number (partial match)"),
    status: str = Query(None, description="Filter by registration status")
):
    """
    Get all users endpoint with filtering and pagination
    
    Requires:
    - Authorization header with Bearer token (custom JWT token)
    
    Query Parameters:
    - page: Page number (default: 1)
    - per_page: Number of users per page (default: 20, max: 100)
    - sort: Sort criteria in JSON format (e.g., [{"id": "name", "desc": false}])
    - name: Filter by user name (partial match)
    - ic_number: Filter by IC number (partial match)
    - status: Filter by registration status (active, inactive, pending)
    
    Returns:
    - Paginated list of users with filtering and sorting applied
    - Total count and pagination metadata
    """
    return await get_all_users_controller(
        request, response, db, page, per_page, sort, name, ic_number, status
    )

