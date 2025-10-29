import os
import boto3
import hmac
import hashlib
import base64
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class CognitoService:
    """AWS Cognito service for user authentication"""
    
    def __init__(self):
        self.client = boto3.client(
            'cognito-idp',
            region_name=os.getenv("AWS_REGION"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        )
        self.user_pool_id = os.getenv("COGNITO_USER_POOL_ID")
        self.client_id = os.getenv("COGNITO_CLIENT_ID")
        # Only set client_secret if it exists and is not empty
        client_secret = os.getenv("COGNITO_CLIENT_SECRET")
        self.client_secret = client_secret if client_secret and client_secret.strip() else None
    
    def _get_secret_hash(self, username: str) -> Optional[str]:
        """Generate secret hash for Cognito authentication"""
        if not self.client_secret:
            return None
        
        message = username + self.client_id
        dig = hmac.new(
            self.client_secret.encode('utf-8'),
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(dig).decode()
    
    def sign_up(self, email: str, password: str, username: str, phone_number: str, name: str) -> Dict[str, Any]:
        """
        Register a new user in Cognito
        
        Args:
            email: User email
            password: User password
            username: Username for Cognito (IC number)
            phone_number: User phone number
            name: User name (optional)
            
        Returns:
            Dict with success status and user information or error message
        """
        try:
            # Build user attributes, only including non-None values
            user_attributes = [
                {'Name': 'email', 'Value': email}
            ]
            
            # Add optional attributes only if they have values
            if name:
                user_attributes.append({'Name': 'name', 'Value': name})
            
            if phone_number:
                user_attributes.append({'Name': 'phone_number', 'Value': phone_number})
            user_attributes.append({'Name': 'email', 'Value': email})
            user_attributes.append({'Name': 'name', 'Value': name})
            user_attributes.append({'Name': 'address', 'Value': 'address'})
            
            params = {
                'ClientId': self.client_id,
                'Username': username,  # Use IC number as Cognito username
                'Password': password,
                'UserAttributes': user_attributes,
            }
            
            # Add secret hash if client secret is configured
            secret_hash = self._get_secret_hash(username)  # Use username for secret hash
            if secret_hash:
                params['SecretHash'] = secret_hash
            
            response = self.client.sign_up(**params)
            
            return {
                "success": True,
                "message": "User registered successfully",
                "user_sub": response['UserSub'],
                "user_confirmed": response['UserConfirmed'],
                "cognito_user_id": response['UserSub']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            logger.error(f"Cognito sign up error: {error_code} - {error_message}")
            
            # Handle specific error cases
            if error_code == 'UsernameExistsException':
                return {
                    "success": False,
                    "message": "An account with this email already exists in Cognito. Please try logging in."
                }
            elif error_code == 'InvalidPasswordException':
                return {
                    "success": False,
                    "message": "Password does not meet requirements. Please ensure it's at least 8 characters long."
                }
            elif error_code == 'InvalidParameterException':
                return {
                    "success": False,
                    "message": f"Invalid parameter: {error_message}"
                }
            else:
                return {
                    "success": False,
                    "message": f"Registration failed: {error_message}"
                }
                
        except Exception as e:
            logger.error(f"Cognito sign up unexpected error: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred during registration"
            }
    
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user with Cognito
        
        Args:
            username: Username (IC number)
            password: User password
            
        Returns:
            Dict with success status and authentication tokens or error message
        """
        try:
            params = {
                'AuthFlow': 'USER_PASSWORD_AUTH',
                'ClientId': self.client_id,
                'AuthParameters': {
                    'USERNAME': username,
                    'PASSWORD': password
                }
            }
            
            # Add secret hash if client secret is configured
            secret_hash = self._get_secret_hash(username)
            if secret_hash:
                params['AuthParameters']['SECRET_HASH'] = secret_hash
            
            response = self.client.initiate_auth(**params)
            
            return {
                "success": True,
                "message": "Authentication successful",
                "id_token": response['AuthenticationResult']['IdToken'],
                "access_token": response['AuthenticationResult']['AccessToken'],
                "refresh_token": response['AuthenticationResult']['RefreshToken'],
                "expires_in": response['AuthenticationResult']['ExpiresIn'],
                "token_type": response['AuthenticationResult']['TokenType']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            logger.error(f"Cognito authentication error: {error_code} - {error_message}")
            
            if error_code == 'NotAuthorizedException':
                return {
                    "success": False,
                    "message": "Invalid IC number or password. Please check your credentials and try again."
                }
            elif error_code == 'UserNotFoundException':
                return {
                    "success": False,
                    "message": "No account found with this IC number. Please sign up first."
                }
            elif error_code == 'UserNotConfirmedException':
                return {
                    "success": False,
                    "message": "Your account is not confirmed. Please check your email for confirmation link."
                }
            else:
                return {
                    "success": False,
                    "message": f"Authentication failed: {error_message}"
                }
                
        except Exception as e:
            logger.error(f"Cognito authentication unexpected error: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred during authentication"
            }
    
    def forgot_password(self, username: str) -> Dict[str, Any]:
        """
        Initiate forgot password flow
        
        Args:
            username: Username (IC number)
            
        Returns:
            Dict with success status and delivery details or error message
        """
        try:
            params = {
                'ClientId': self.client_id,
                'Username': username
            }
            
            # Add secret hash if client secret is configured
            secret_hash = self._get_secret_hash(username)
            if secret_hash:
                params['SecretHash'] = secret_hash
            
            response = self.client.forgot_password(**params)
            
            return {
                "success": True,
                "message": "Password reset code sent successfully. Please check your email.",
                "code_delivery_details": response.get('CodeDeliveryDetails', {})
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            logger.error(f"Cognito forgot password error: {error_code} - {error_message}")
            
            if error_code == 'UserNotFoundException':
                return {
                    "success": False,
                    "message": "No account found with this email address."
                }
            elif error_code == 'InvalidParameterException':
                return {
                    "success": False,
                    "message": "Invalid email address provided."
                }
            elif error_code == 'LimitExceededException':
                return {
                    "success": False,
                    "message": "Too many requests. Please try again later."
                }
            else:
                return {
                    "success": False,
                    "message": f"Password reset failed: {error_message}"
                }
                
        except Exception as e:
            logger.error(f"Cognito forgot password unexpected error: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred while processing password reset"
            }
    
    def confirm_forgot_password(self, username: str, confirmation_code: str, new_password: str) -> Dict[str, Any]:
        """
        Confirm forgot password with code
        
        Args:
            username: Username (IC number)
            confirmation_code: Code received via email
            new_password: New password
            
        Returns:
            Dict with success status or error message
        """
        try:
            params = {
                'ClientId': self.client_id,
                'Username': username,
                'ConfirmationCode': confirmation_code,
                'Password': new_password
            }
            
            # Add secret hash if client secret is configured
            secret_hash = self._get_secret_hash(username)
            if secret_hash:
                params['SecretHash'] = secret_hash
            
            self.client.confirm_forgot_password(**params)
            
            return {
                "success": True,
                "message": "Password reset successful. You can now log in with your new password."
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            logger.error(f"Cognito confirm forgot password error: {error_code} - {error_message}")
            
            if error_code == 'CodeMismatchException':
                return {
                    "success": False,
                    "message": "Invalid verification code. Please check the code and try again."
                }
            elif error_code == 'ExpiredCodeException':
                return {
                    "success": False,
                    "message": "Verification code has expired. Please request a new password reset."
                }
            elif error_code == 'InvalidPasswordException':
                return {
                    "success": False,
                    "message": "Password does not meet requirements. Please ensure it's at least 8 characters long."
                }
            elif error_code == 'UserNotFoundException':
                return {
                    "success": False,
                    "message": "No account found with this email address."
                }
            else:
                return {
                    "success": False,
                    "message": f"Password reset confirmation failed: {error_message}"
                }
                
        except Exception as e:
            logger.error(f"Cognito confirm forgot password unexpected error: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred while confirming password reset"
            }
    
    def get_user(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from access token
        
        Args:
            access_token: Cognito access token
            
        Returns:
            Dict with user information or error message
        """
        try:
            response = self.client.get_user(AccessToken=access_token)
            
            # Parse user attributes
            user_attributes = {}
            for attr in response['UserAttributes']:
                user_attributes[attr['Name']] = attr['Value']
            
            return {
                "success": True,
                "username": response['Username'],
                "user_attributes": user_attributes
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            logger.error(f"Cognito get user error: {error_code} - {error_message}")
            
            return {
                "success": False,
                "message": f"Failed to get user information: {error_message}"
            }
                
        except Exception as e:
            logger.error(f"Cognito get user unexpected error: {e}")
            return {
                "success": False,
                "message": "An unexpected error occurred while getting user information"
            }
    
    def admin_confirm_user(self, username: str) -> Dict[str, Any]:
        """
        Admin confirm user (bypass email verification)
        
        Args:
            username: Username/email to confirm
            
        Returns:
            Dict with success status
        """
        try:
            self.client.admin_confirm_sign_up(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            
            return {
                "success": True,
                "message": "User confirmed successfully"
            }
            
        except ClientError as e:
            logger.error(f"Admin confirm user error: {e}")
            return {
                "success": False,
                "message": f"Failed to confirm user: {e.response['Error']['Message']}"
            }

# Create singleton instance
cognito_service = CognitoService()

