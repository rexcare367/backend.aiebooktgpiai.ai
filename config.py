import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    EMAIL_FROM = os.getenv("EMAIL_FROM")
    BREVO_API_KEY: str = os.getenv("BREVO_API_KEY")
    FROM_NAME = os.getenv("FROM_NAME", "AI eBOOK Support")
    
    # AWS Cognito Settings
    AWS_REGION = os.getenv("AWS_REGION")
    COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
    COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
    # Only set if client secret is actually configured in Cognito app client
    client_secret = os.getenv("COGNITO_CLIENT_SECRET")
    COGNITO_CLIENT_SECRET = client_secret if client_secret and client_secret.strip() else None
    
    # AWS Credentials
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")


settings = Settings()
