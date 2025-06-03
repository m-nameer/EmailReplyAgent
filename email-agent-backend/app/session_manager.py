from typing import Optional, Dict
from threading import Lock


class UserSession:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.active_draft_id: Optional[str] = None
        self.in_edit_mode: bool = False


class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, UserSession] = {}
        self.lock = Lock()

    def get_session(self, user_id: str) -> UserSession:
        with self.lock:
            if user_id not in self.sessions:
                self.sessions[user_id] = UserSession(user_id)
            return self.sessions[user_id]

    def clear_session(self, user_id: str):
        with self.lock:
            if user_id in self.sessions:
                del self.sessions[user_id]


# Global instance
session_manager = SessionManager()
