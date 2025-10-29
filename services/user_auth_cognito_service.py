import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_
from database.models import User
from schemas.models import (
    UserLoginRequest, 
    UserGoogleLoginRequest, 
    UserSignupRequest, 
    ForgotPasswordRequest, 
    CognitoResetPasswordRequest
)
from services.cognito_service import cognito_service
from services.brevo_service import BrevoEmailService
import logging

logger = logging.getLogger(__name__)

# JWT Configuration (for backward compatibility and custom tokens)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


def create_jwt_token(user_id: str, email: str) -> str:
    """Create a JWT token for user authentication (custom token for backend use)"""
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("JWT token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.error("Invalid JWT token")
        return None


def user_cognito_login(login_data: UserLoginRequest, db: Session) -> Dict[str, Any]:
    """
    User login with Cognito authentication
    Validates against database and authenticates with Cognito
    """
    try:
        # Find user by email or ic_number in database
        user = db.query(User).filter(
            or_(User.email == login_data.identifier, User.ic_number == login_data.identifier)
        ).first()
        
        if not user:
            return {
                "success": False,
                "message": "Invalid email/IC number or password. Please check your credentials and try again."
            }
        
        # Authenticate with Cognito using IC number as username
        cognito_result = cognito_service.authenticate(user.ic_number, login_data.password)
        
        if not cognito_result["success"]:
            return cognito_result
        
        # Update last login
        user.updated_at = datetime.now()
        db.commit()
        
        # Create custom JWT token for backward compatibility
        custom_token = create_jwt_token(str(user.id), user.email)
        
        return {
            "success": True,
            "message": "Login successful",
            "token": custom_token,  # Custom JWT token
            "cognito_tokens": {
                "id_token": cognito_result["id_token"],
                "access_token": cognito_result["access_token"],
                "refresh_token": cognito_result["refresh_token"],
                "expires_in": cognito_result["expires_in"]
            },
            "user_id": str(user.id),
            "data": {
                "id": str(user.id),
                "email": user.email,
                "ic_number": user.ic_number,
                "name": user.name,
                "registration_status": user.registration_status,
                "avatar_url": user.avatar_url,
                "birth": user.birth,
                "address": user.address,
                "parent": user.parent,
                "school_id": str(user.school_id) if user.school_id else None,
                "rewards": user.rewards,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None
            }
        }
        
    except Exception as e:
        logger.error(f"Cognito login error: {e}")
        db.rollback()
        return {
            "success": False,
            "message": "An error occurred during login. Please try again later."
        }


def user_google_login(login_data: UserGoogleLoginRequest, db: Session) -> Dict[str, Any]:
    """User login with email (Google OAuth)"""
    try:
        # Find user by email
        user = db.query(User).filter(User.email == login_data.email).first()
        
        if not user:
            return {
                "success": False,
                "message": "No account found with this email address. Please sign up first."
            }
        
        # Check if user is active
        if user.registration_status != 'active':
            return {
                "success": False,
                "message": "Your account is not active. Please contact administrator to activate your account."
            }
        
        # Create JWT token
        token = create_jwt_token(str(user.id), user.email)
        
        # Update last login
        user.updated_at = datetime.now()
        db.commit()
        
        return {
            "success": True,
            "message": "Login successful",
            "token": token,
            "user_id": str(user.id),
            "data": {
                "id": str(user.id),
                "email": user.email,
                "ic_number": user.ic_number,
                "name": user.name,
                "registration_status": user.registration_status,
                "avatar_url": user.avatar_url,
                "birth": user.birth,
                "address": user.address,
                "parent": user.parent,
                "school_id": str(user.school_id) if user.school_id else None,
                "rewards": user.rewards,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None
            }
        }
        
    except Exception as e:
        logger.error(f"Google login error: {e}")
        db.rollback()
        return {
            "success": False,
            "message": "An error occurred during login. Please try again later."
        }


async def user_cognito_signup(signup_data: UserSignupRequest, db: Session) -> Dict[str, Any]:
    """
    User signup with Cognito registration
    Validates IC number exists in database before creating Cognito account
    """
    try:
        # Step 1: Check if IC number exists in database
        existing_user = db.query(User).filter(User.ic_number == signup_data.ic_number).first()
        
        if not existing_user:
            return {
                "success": False,
                "message": "User with this IC number does not exist in the system. Please contact administrator to add your IC number to the system."
            }
        
        # Step 4: Register user with Cognito
        # Use existing user's name, or default to email username if name is not set
        user_name = existing_user.name if existing_user.name else signup_data.email.split('@')[0]
        
        cognito_result = cognito_service.sign_up(
            email=signup_data.email,
            password=signup_data.password,
            username=signup_data.ic_number,
            phone_number=signup_data.phone,
            name=user_name
        )
        
        if not cognito_result["success"]:
            return cognito_result
        
        # Step 5: Auto-confirm user in Cognito (skip email verification)
        confirm_result = cognito_service.admin_confirm_user(signup_data.ic_number)
        if not confirm_result["success"]:
            logger.warning(f"Failed to auto-confirm user: {confirm_result['message']}")
        
        # Step 6: Update database with user information
        existing_user.email = signup_data.email
        existing_user.phone = signup_data.phone
        existing_user.registration_status = 'active'
        existing_user.updated_at = datetime.now()
        # Note: We don't store password_hash anymore as Cognito handles authentication
        
        db.commit()
        
        # Step 7: Create custom JWT token
        token = create_jwt_token(str(existing_user.id), existing_user.email)
        
        # Step 8: Send welcome email
        try:
            await BrevoEmailService.send_welcome_email(existing_user.email, existing_user.name)
        except Exception as e:
            logger.error(f"Failed to send welcome email: {e}")
        
        return {
            "success": True,
            "message": "Registration successful! Your account has been created and activated.",
            "token": token,
            "user_id": str(existing_user.id),
            "cognito_user_id": cognito_result.get("cognito_user_id"),
            "data": {
                "id": str(existing_user.id),
                "email": existing_user.email,
                "ic_number": existing_user.ic_number,
                "name": existing_user.name,
                "registration_status": existing_user.registration_status,
                "school_id": str(existing_user.school_id) if existing_user.school_id else None,
            }
        }
        
    except Exception as e:
        logger.error(f"Cognito signup error: {e}")
        db.rollback()
        return {
            "success": False,
            "message": "An error occurred during registration. Please try again later or contact support."
        }


async def forgot_password_cognito(forgot_data: ForgotPasswordRequest, db: Session) -> Dict[str, Any]:
    """
    Send password reset code via Cognito
    """
    try:
        # Check if user exists in database
        user = db.query(User).filter(User.email == forgot_data.email).first()
        
        if not user:
            return {
                "success": False,
                "message": "No account found with this email address. Please check your email or contact support."
            }
        
        # Check if user is active
        if user.registration_status != 'active':
            return {
                "success": False,
                "message": "Account is not active. Please contact administrator to activate your account."
            }
        
        # Initiate forgot password flow with Cognito using IC number as username
        cognito_result = cognito_service.forgot_password(user.ic_number)
        
        return cognito_result
        
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return {
            "success": False,
            "message": "An error occurred while processing your request. Please try again later."
        }


async def reset_password_cognito(reset_data: CognitoResetPasswordRequest, db: Session) -> Dict[str, Any]:
    """
    Reset password using Cognito confirmation code
    """
    try:
        # Verify user exists in database
        user = db.query(User).filter(User.email == reset_data.email).first()
        
        if not user:
            return {
                "success": False,
                "message": "User account not found. Please contact support."
            }
        
        # Confirm password reset with Cognito using IC number as username
        cognito_result = cognito_service.confirm_forgot_password(
            username=user.ic_number,
            confirmation_code=reset_data.confirmation_code,
            new_password=reset_data.new_password
        )
        
        if cognito_result["success"]:
            # Update database timestamp
            user.updated_at = datetime.now()
            db.commit()
            
            # Send confirmation email
            try:
                await BrevoEmailService.send_notification_email(
                    email=user.email,
                    subject="Password Reset Successful",
                    message="Your password has been successfully reset. If you did not perform this action, please contact support immediately.",
                    user_name=user.name
                )
            except Exception as e:
                logger.error(f"Failed to send password reset confirmation email: {e}")
        
        return cognito_result
        
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        db.rollback()
        return {
            "success": False,
            "message": "An error occurred while resetting your password. Please try again later."
        }


def get_user_profile(user_id: str, db: Session) -> Optional[Dict[str, Any]]:
    """Get user profile by ID"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            return None
        
        return {
            "id": str(user.id),
            "ic_number": user.ic_number,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "avatar_url": user.avatar_url,
            "birth": user.birth,
            "address": user.address,
            "parent": user.parent,
            "school_id": str(user.school_id) if user.school_id else None,
            "registration_status": user.registration_status,
            "rewards": user.rewards,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None
        }
        
    except Exception as e:
        logger.error(f"Get user profile error: {e}")
        return None


def get_all_users(db: Session, page: int = 1, per_page: int = 20, sort: str = None, name: str = None, ic_number: str = None, status: str = None) -> Dict[str, Any]:
    """Get all users with optional filtering and pagination"""
    try:
        query = db.query(User)
        
        # Default sorting by created_at desc
        query = query.order_by(User.created_at.desc())
        
        # Get total count before pagination
        total_count = query.count()
        
        # Apply pagination
        users = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Serialize users
        serialized_users = []
        for user in users:
            user_data = {
                "id": str(user.id),
                "ic_number": user.ic_number,
                "name": user.name,
                "email": user.email_address,
                "avatar_url": user.avatar_url,
            }
            serialized_users.append(user_data)
        
        return {
            "success": True,
            "users": serialized_users,
            "total_count": total_count,
            "page": page,
            "per_page": per_page,
            "total_pages": (total_count + per_page - 1) // per_page
        }
        
    except Exception as e:
        logger.error(f"Get all users error: {e}")
        db.rollback()
        return {
            "success": False,
            "message": "An error occurred while fetching users. Please try again later.",
            "users": [],
            "total_count": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0
        }
