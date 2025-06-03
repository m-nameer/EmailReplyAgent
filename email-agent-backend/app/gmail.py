import os
from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import models, auth
from sqlalchemy.orm import Session
import base64
from email.mime.text import MIMEText
import json

from dotenv import load_dotenv
load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

import os
print(os.getenv("GOOGLE_CLIENT_ID"))
print(os.getenv("GOOGLE_CLIENT_SECRET"))

def get_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES
    )

def generate_auth_url(user_id: str):
    flow = get_flow()
    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    state = f"user-{user_id}"
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state
    )
    return auth_url, state

def save_gmail_credentials(user: models.User, state: str, code: str, db: Session):
    flow = get_flow()
    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    flow.fetch_token(code=code)

    creds = flow.credentials
    # user.gmail_token = {
    #     "token": creds.token,
    #     "refresh_token": creds.refresh_token,
    #     "token_uri": creds.token_uri,
    #     "client_id": creds.client_id,
    #     "client_secret": creds.client_secret,
    #     "scopes": creds.scopes
    # }
    

    user.gmail_token = json.dumps({
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    })
    db.commit()

def get_gmail_service(user: models.User):
    if not user.gmail_token:
        raise HTTPException(status_code=400, detail="Gmail not connected")

    creds_dict = json.loads(user.gmail_token)
    creds = Credentials(**creds_dict)
    return build("gmail", "v1", credentials=creds)



def encode_email_raw(sender, to, subject, body):
    message = MIMEText(body)
    message["to"] = to
    message["from"] = sender
    message["subject"] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return raw

