from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect, Body
from fastapi import Depends
from googleapiclient.errors import HttpError
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware 
from sqlalchemy.orm import Session
import models, schemas, auth, database
import uuid
import gmail
import whatsapp
from pydantic import BaseModel
from datetime import datetime
from gmail import get_gmail_service, encode_email_raw
from ai_agent import generate_reply
from models import DraftSession
from fastapi.responses import JSONResponse, HTMLResponse
import asyncio
from database import SessionLocal
import time
import httpx
from session_manager import session_manager




app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://email-reply-agent.vercel.app/"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class MessageRequest(BaseModel):
    recipient: str
    message: str

models.Base.metadata.create_all(bind=database.engine)

@app.post("/register", response_model=schemas.UserOut)
def register(user_data: schemas.UserCreate, db: Session = Depends(auth.get_db)):
    user_exists = db.query(models.User).filter(models.User.email == user_data.email).first()
    if user_exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = models.User(
        id=str(uuid.uuid4()),
        email=user_data.email,
        password_hash=auth.get_password_hash(user_data.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(auth.get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)

    print(user)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    user.login_time = datetime.utcnow()
    db.commit()

    token = auth.create_access_token(data={"sub": user.id})

    response = JSONResponse({"access_token": token, "token_type": "bearer"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=False,
        secure=False,       # Change to True in production with HTTPS
        samesite="Lax",     # Or "None" if frontend/backend are on different origins
        max_age=3600
    )
    print("Toekn: ",token)
    return response


@app.get("/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user



@app.get("/email/authorize")
def authorize_gmail(current_user: models.User = Depends(auth.get_current_user)):
    url, state = gmail.generate_auth_url(current_user.id)
    return {"auth_url": url}

@app.get("/email/oauth2callback")
def oauth2_callback(request: Request, code: str, state: str = None, db: Session = Depends(auth.get_db)):
    if not state or not state.startswith("user-"):
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    user_id = state[5:]  # Remove "user-" prefix
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    gmail.save_gmail_credentials(user, state=state, code=code, db=db)
    token = auth.create_access_token(data={"sub": user.id})
    # response = RedirectResponse("http://localhost:3000/dashboard?gmail_connected=true")
    response = HTMLResponse(f"""
    <html>
    <script>
        window.opener.postMessage({{"type": "gmail_connected"}}, "http://localhost:3000");
        window.close();
    </script>
    </html>
    """)
    response.set_cookie(
    key="access_token",
    value=token,
    httponly=True,
    secure=True,       # ⚠️ Set to False in dev, True in prod (needs HTTPS)
    samesite="None",   # For cross-site (localhost:8000 → 3000)
    max_age=3600       # 1 hour
)
    return response

@app.get("/email/status")
def email_status(current_user: models.User = Depends(auth.get_current_user)):
    return {"connected": current_user.gmail_token is not None}


@app.post("/email/disconnect")
def disconnect_gmail(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    current_user.gmail_token = None
    db.commit()
    return {"disconnected": True}


@app.get("/whatsapp/connect")
async def connect_whatsapp(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    result = await whatsapp.get_status(current_user.id)
    if result.get("status") == "connected" and result.get("jid"):
        current_user.whatsapp_jid = result.get("jid")
        db.commit()
        return {"status": "connected", "jid": result.get("jid")}

    qr_result = await whatsapp.get_qr_code(current_user.id)
    qr_code = qr_result.get("qr")

    print(f"qr code: {qr_code} for User: {current_user.email}")

    asyncio.create_task(monitor_whatsapp_connection(current_user.id))

    return {"status": "need_scan", "qr": qr_code}


async def monitor_whatsapp_connection(user_id: str):
    print('Started Monitoring!!!!')
    db = SessionLocal()
    try:
        waited = 0
        max_wait = 12000
        while waited < max_wait or status.get("status") == "connected":
            status = await whatsapp.get_status(user_id)
            # print("Got Status: ",status)
            jid = status.get("jid")
            if status.get("status") == "connected" and jid:
                user = db.query(models.User).filter(models.User.id == user_id).first()
                if user:
                    user.whatsapp_jid = jid
                    db.commit()
                    # print(f"✅ WhatsApp connected for {user.email} - JID saved: {jid}")
                return
            await asyncio.sleep(5)
            waited += 5
        print(f"⏰ Timeout waiting for WhatsApp connection for user {user_id}")
    except Exception as e:
        print(f"❌ Error monitoring WhatsApp connection for user {user_id}: {e}")
    finally:
        db.close()





@app.get("/whatsapp/status")
async def status(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    result = await whatsapp.get_status(current_user.id)

    if result.get("status") == "connected":
        current_user.whatsapp_jid = result.get("jid")
    else:
        current_user.whatsapp_jid = None
    db.commit()

    return result

@app.post("/whatsapp/send")
async def send_msg(msg: MessageRequest, current_user: models.User = Depends(auth.get_current_user)):
    if not current_user.whatsapp_jid:
        raise HTTPException(status_code=400, detail="WhatsApp not connected")
    return await whatsapp.send_message(current_user.id, msg.recipient, msg.message)


@app.get("/email/poll")
async def poll_email(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    if not current_user.agent_enabled:
        return {"message": "Agent is turned off", "processed": 0}
    service = get_gmail_service(current_user)
    login_time = int(current_user.login_time.timestamp())
    gmail_query = f"category:primary after:{login_time}"

    results = service.users().messages().list(userId="me", labelIds=["INBOX"], q=gmail_query).execute()
    messages = results.get("messages", [])

    summary_lines = []
    new_drafts = []

    for msg in messages:
        full_msg = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        headers = full_msg["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        from_email = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
        snippet = full_msg.get("snippet", "")

        draft = DraftSession(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            email_subject=subject,
            email_from=from_email,
            email_snippet=snippet,
            draft_reply="",
        )
        db.add(draft)
        db.commit()

        new_drafts.append(draft)
        summary_lines.append(f"{len(summary_lines)+1}️⃣ From: {from_email} | Subject: {subject}")

        # Mark as read
        service.users().messages().modify(
            userId="me",
            id=msg["id"],
            body={"removeLabelIds": ["UNREAD"]}
        ).execute()

    if new_drafts and current_user.whatsapp_jid:
        message = "\n".join([
            "📬 You have new emails:",
            *summary_lines,
            "Reply with: /select 1 (or 2, 3...)"
        ])
        await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, message)

    return {"processed": len(new_drafts)}


class FeedbackRequest(BaseModel):
    message: str


# @app.post("/whatsapp/feedback")
# async def whatsapp_feedback(
#     payload: FeedbackRequest,
#     current_user: models.User = Depends(auth.get_current_user),
#     db: Session = Depends(auth.get_db)
# ):
#     text = payload.message.strip()

#     if text.lower() == "/list":
#         drafts = db.query(DraftSession).filter(
#             DraftSession.user_id == current_user.id,
#             DraftSession.status.in_(["pending", "edited", "cancelled"])
#         ).all()

#         if not drafts:
#             await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "📭 No emails to review.")
#             return {"message": "No drafts found"}

#         message_lines = ["📋 Draft Emails:"]
#         for idx, draft in enumerate(drafts, start=1):
#             status = "Saved in draft" if draft.status == "cancelled" else "Pending"
#             message_lines.append(f"{idx}. From: {draft.email_from} | Subject: {draft.email_subject} [{status}]")

#         await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "\n".join(message_lines))
#         return {"message": "Draft list sent"}

#     elif text.lower().startswith("/select"):
#         try:
#             index = int(text.split()[1]) - 1
#         except (IndexError, ValueError):
#             return {"message": "❌ Usage: /select <number>"}

#         drafts = db.query(DraftSession).filter(
#             DraftSession.user_id == current_user.id,
#             DraftSession.status.in_(["pending", "edited", "cancelled"])
#         ).all()

#         if index < 0 or index >= len(drafts):
#             return {"message": "❌ Invalid selection index"}

#         selected = drafts[index]
#         current_user.active_draft_id = selected.id
#         db.commit()

#         msg_parts = [
#             f"📩 Selected Email:\nFrom: {selected.email_from}\nSubject: {selected.email_subject}",
#             f"\n📎 Snippet:\n{selected.email_snippet}"
#         ]

#         if selected.status == "cancelled" and selected.draft_reply:
#             msg_parts.append(f"\n💬 Previously Saved Draft:\n{selected.draft_reply}")
#         elif not selected.draft_reply:
#             ai_reply = await generate_reply(selected.email_subject, selected.email_snippet, selected.email_from)
#             selected.draft_reply = ai_reply
#             db.commit()
#             msg_parts.append(f"\n🤖 AI Draft:\n{ai_reply}")
#         else:
#             msg_parts.append(f"\n💬 Current Draft:\n{selected.draft_reply}")

#         msg_parts.append("\nYou can now type updates, or use /send or /cancel.")
#         await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "\n".join(msg_parts))
#         return {"message": "Draft selected"}

#     elif text.lower() == "/send":
#         if not current_user.active_draft_id:
#             return {"message": "❌ No active draft selected. Use /list and /select first."}

#         draft = db.query(DraftSession).filter_by(id=current_user.active_draft_id, user_id=current_user.id).first()
#         if not draft or draft.status not in ["pending", "edited"]:
#             return {"message": "❌ Invalid or already sent draft."}

#         try:
#             service = get_gmail_service(current_user)
#             raw = encode_email_raw(current_user.email, draft.email_from, draft.email_subject, draft.draft_reply)
#             service.users().messages().send(userId="me", body={"raw": raw}).execute()

#             draft.status = "sent"
#             current_user.active_draft_id = None
#             db.commit()

#             await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "✅ Email sent successfully.")
#             return {"message": "Email sent"}
#         except Exception as e:
#             return {"message": f"❌ Failed to send email: {e}"}

#     elif text.lower() == "/cancel":
#         if not current_user.active_draft_id:
#             return {"message": "❌ No active draft to cancel."}

#         draft = db.query(DraftSession).filter_by(id=current_user.active_draft_id, user_id=current_user.id).first()
#         if not draft:
#             return {"message": "❌ Draft not found."}

#         draft.status = "cancelled"
#         current_user.active_draft_id = None
#         db.commit()

#         await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "🚫 Draft cancelled and saved.")
#         return {"message": "Cancelled"}
    
#     elif text.lower().startswith("/edit"):
#         if not current_user.active_draft_id:
#             return {"message": "❌ No active draft selected. Use /list and /select first."}

#         draft = db.query(DraftSession).filter_by(id=current_user.active_draft_id, user_id=current_user.id).first()
#         if not draft:
#             return {"message": "❌ Draft not found."}

#         user_instruction = text[5:].strip()
#         if not user_instruction:
#             return {"message": "❌ No instructions provided for editing."}

#         # Generate updated draft using AI agent
#         updated_reply = await generate_reply(
#             subject=draft.email_subject,
#             snippet=draft.email_snippet,
#             from_email=draft.email_from,
#             user_instruction=user_instruction
#         )

#         draft.draft_reply = updated_reply
#         draft.status = "edited"
#         db.commit()

#         await whatsapp.send_message(current_user.id, current_user.whatsapp_jid,
#             f"✏️ Updated draft:\n{draft.draft_reply}")
#         return {"message": "Draft updated"}
    
#     else:
#         print("Incorrect option selected!!")

#     # else:
#     #     # Handle free-form updates
#     #     if not current_user.active_draft_id:
#     #         return {"message": "❌ No active draft selected. Use /list and /select."}

#     #     draft = db.query(DraftSession).filter_by(id=current_user.active_draft_id, user_id=current_user.id).first()
#     #     if not draft:
#     #         return {"message": "❌ Draft not found."}

#     #     draft.draft_reply += f"\n\n📝 Edit: {text}"
#     #     draft.status = "edited"
#     #     db.commit()

#     #     await whatsapp.send_message(current_user.id, current_user.whatsapp_jid,
#     #         f"✏️ Reply updated:\n{draft.draft_reply}")
#     #     return {"message": "Draft updated"}

    

@app.post("/whatsapp/feedback")
async def whatsapp_feedback(
    payload: FeedbackRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db)
):
    text = payload.message.strip()
    session = session_manager.get_session(current_user.id)

    if text.lower() == "/list":
        drafts = db.query(DraftSession).filter(
            DraftSession.user_id == current_user.id,
            DraftSession.status.in_(["pending", "edited", "cancelled"])
        ).all()

        if not drafts:
            await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "📭 No emails to review.")
            return {"message": "No drafts found"}

        message_lines = ["📋 Draft Emails:"]
        for idx, draft in enumerate(drafts, start=1):
            status = "Saved in draft" if draft.status == "cancelled" else "Pending"
            message_lines.append(f"{idx}. From: {draft.email_from} \n\n Subject: {draft.email_subject} \n\n Status: [{status}]")

        await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "\n".join(message_lines))
        return {"message": "Draft list sent"}

    elif text.lower().startswith("/select"):
        try:
            index = int(text.split()[1]) - 1
        except (IndexError, ValueError):
            return {"message": "❌ Usage: /select <number>"}

        drafts = db.query(DraftSession).filter(
            DraftSession.user_id == current_user.id,
            DraftSession.status.in_(["pending", "edited", "cancelled"])
        ).all()

        if index < 0 or index >= len(drafts):
            return {"message": "❌ Invalid selection index"}

        selected = drafts[index]
        session.active_draft_id = selected.id
        session.in_edit_mode = False

        msg_parts = [
            f"📩 Selected Email:\nFrom: {selected.email_from}\nSubject: {selected.email_subject}",
            f"\n📎 Snippet:\n{selected.email_snippet}"
        ]

        if selected.status == "cancelled" and selected.draft_reply:
            msg_parts.append(f"\n💬 Previously Saved Draft:\n{selected.draft_reply}")
        elif not selected.draft_reply:
            ai_reply = await generate_reply(selected.email_subject, selected.email_snippet, selected.email_from)
            selected.draft_reply = ai_reply
            db.commit()
            msg_parts.append(f"\n🤖 AI Draft:\n{ai_reply}")
        else:
            msg_parts.append(f"\n💬 Current Draft:\n{selected.draft_reply}")

        msg_parts.append("\n\nYou can now type updates, or use /edit, /send or /cancel.")
        await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "\n".join(msg_parts))
        return {"message": "Draft selected"}

    elif text.lower() == "/edit":
        if not session.active_draft_id:
            return {"message": "❌ No draft selected. Use /select first."}

        session.in_edit_mode = True
        await whatsapp.send_message(
            current_user.id,
            current_user.whatsapp_jid,
            "✏️ You are now in edit mode. Send instructions to update the draft."
        )
        return {"message": "Entered edit mode"}

    elif text.lower() == "/send":
        if not session.active_draft_id:
            return {"message": "❌ No active draft selected."}

        draft = db.query(DraftSession).filter_by(id=session.active_draft_id, user_id=current_user.id).first()
        if not draft:
            return {"message": "❌ Draft not found."}

        try:
            service = get_gmail_service(current_user)
            raw = encode_email_raw(current_user.email, draft.email_from, draft.email_subject, draft.draft_reply)
            service.users().messages().send(userId="me", body={"raw": raw}).execute()

            draft.status = "sent"
            db.commit()
            session_manager.clear_session(current_user.id)

            await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "✅ Email sent successfully.")
            return {"message": "Email sent"}
        except Exception as e:
            return {"message": f"❌ Failed to send email: {e}"}

    elif text.lower() == "/cancel":
        if not session.active_draft_id:
            return {"message": "❌ No active draft to cancel."}

        draft = db.query(DraftSession).filter_by(id=session.active_draft_id, user_id=current_user.id).first()
        if not draft:
            return {"message": "❌ Draft not found."}

        draft.status = "cancelled"
        db.commit()
        session_manager.clear_session(current_user.id)

        await whatsapp.send_message(current_user.id, current_user.whatsapp_jid, "🚫 Draft cancelled and saved.")
        return {"message": "Cancelled"}

    elif session.in_edit_mode:
        if not session.active_draft_id:
            return {"message": "❌ No active draft."}

        draft = db.query(DraftSession).filter_by(id=session.active_draft_id, user_id=current_user.id).first()
        if not draft:
            return {"message": "❌ Draft not found."}

        updated_reply = await generate_reply(
            subject=draft.email_subject,
            snippet=draft.email_snippet,
            from_email=draft.email_from,
            user_instruction=text
        )

        draft.draft_reply = updated_reply
        draft.status = "edited"
        db.commit()

        await whatsapp.send_message(current_user.id, current_user.whatsapp_jid,
            f"✏️ Updated reply:\n{draft.draft_reply}")
        return {"message": "Draft updated"}

    else:
        return {"message": "❓ Unknown command. Use /list, /select, /edit, /send or /cancel."}

   



@app.post("/whatsapp/disconnect")
async def disconnect_whatsapp(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    # Invalidate the jid in DB
    current_user.whatsapp_jid = None
    db.commit()

    # Notify Go server
    async with httpx.AsyncClient() as client:
        try:
            await client.post(f"http://localhost:8080/api/whatsapp/{current_user.id}/disconnect")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"WhatsApp backend disconnect failed: {e}")

    return {"disconnected": True}




class IncomingMessage(BaseModel):
    user_id: str
    content: str

@app.post("/internal/incoming-message")
async def receive_incoming_message(msg: IncomingMessage, db: Session = Depends(auth.get_db)):
    user = db.query(models.User).filter(models.User.id == msg.user_id).first()
    if not user or not user.whatsapp_jid:
        return {"error": "User not found or not connected"}

    print(f"📩 Received message from {user.email}: {msg.content}")

    # Reuse your feedback logic by directly calling the handler
    payload = FeedbackRequest(message=msg.content)
    return await whatsapp_feedback(payload, current_user=user, db=db)




@app.get("/agent/status")
def get_agent_status(current_user: models.User = Depends(auth.get_current_user)):
    return {"enabled": current_user.agent_enabled}

@app.post("/agent/toggle")
def toggle_agent(status: dict = Body(...), current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    current_user.agent_enabled = status.get("enabled", False)
    db.commit()
    return {"enabled": current_user.agent_enabled}



async def background_polling_loop():
    print("✅ Background polling started...")
    while True:
        try:
            db: Session = SessionLocal()
            users = db.query(models.User).filter(
                models.User.gmail_token.isnot(None),
                models.User.whatsapp_jid.isnot(None),
                models.User.agent_enabled == True
            ).all()

            for user in users:
                try:
                    service = get_gmail_service(user)
                    login_time = int(user.login_time.timestamp())
                    gmail_query = f"category:primary after:{login_time}"

                    results = service.users().messages().list(
                        userId="me", labelIds=["INBOX"], q=gmail_query
                    ).execute()
                    messages = results.get("messages", [])

                    new_notifications = []

                    for msg in messages:
                        full_msg = service.users().messages().get(
                            userId="me", id=msg["id"], format="full"
                        ).execute()
                        headers = full_msg["payload"]["headers"]
                        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
                        from_email = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
                        snippet = full_msg.get("snippet", "")

                        existing = db.query(models.DraftSession).filter_by(
                            user_id=user.id,
                            email_subject=subject,
                            email_from=from_email
                        ).first()

                        if existing:
                            continue  # Already tracked

                        draft = models.DraftSession(
                            id=str(uuid.uuid4()),
                            user_id=user.id,
                            email_subject=subject,
                            email_from=from_email,
                            email_snippet=snippet,
                            draft_reply="",
                            status="pending"
                        )
                        db.add(draft)
                        db.commit()

                        new_notifications.append((from_email, subject))

                        # Mark as read in Gmail
                        service.users().messages().modify(
                            userId="me",
                            id=msg["id"],
                            body={"removeLabelIds": ["UNREAD"]}
                        ).execute()

                    if new_notifications:
                        lines = ["📬 New Emails Received:"]
                        for i, (sender, subject) in enumerate(new_notifications, start=1):
                            lines.append(f"{i}. From: {sender} | Subject: {subject}")
                        lines.append("Reply with /list to view or /select <number> to act.")
                        await whatsapp.send_message(user.id, user.whatsapp_jid, "\n".join(lines))

                except Exception as e:
                    print(f"❌ Error for user {user.email}: {e}")

        except Exception as e:
            print("❌ Global polling error:", e)
        finally:
            db.close()

        await asyncio.sleep(20)


@app.on_event("startup")
async def start_background_tasks():
    asyncio.create_task(background_polling_loop())