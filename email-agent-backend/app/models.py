from sqlalchemy import Column, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
import datetime


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    whatsapp_jid = Column(String, nullable=True)
    gmail_token = Column(Text, nullable=True)
    login_time = Column(DateTime, default=datetime.datetime.utcnow)
    agent_enabled = Column(Boolean, default=False)
    active_draft_id = Column(String, ForeignKey("draft_sessions.id"), nullable=True)

    # Explicit foreign_keys definition to resolve ambiguity
    drafts = relationship(
        "DraftSession",
        foreign_keys="[DraftSession.user_id]",
        back_populates="user"
    )

    active_draft = relationship(
        "DraftSession",
        foreign_keys="[User.active_draft_id]",
        uselist=False
    )


class DraftSession(Base):
    __tablename__ = "draft_sessions"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    email_subject = Column(String)
    email_from = Column(String)
    email_snippet = Column(Text)
    draft_reply = Column(Text)
    status = Column(String, default="pending")  # pending, edited, sent, cancelled

    user = relationship(
        "User",
        foreign_keys="[DraftSession.user_id]",
        back_populates="drafts"
    )