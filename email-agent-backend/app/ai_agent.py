import aiohttp
import asyncio
import traceback

async def generate_reply(subject: str, snippet: str, from_email: str, user_instruction: str = "") -> str:
    prompt = f"""
You are an AI assistant helping to draft email replies.

Email Subject: {subject}
From: {from_email}
Email Snippet: {snippet}

User Instruction: {user_instruction}

Please draft a professional and concise reply. Follow user's instructions strictly.
"""

    payload = {
        "model": "gemma3:1b",  # Change to "llama3" or another if needed
        "messages": [
            {"role": "system", "content": "You are an AI assistant that drafts email replies."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "stream": False
    }

    url = "http://localhost:11434/api/chat"

    try:
        timeout = aiohttp.ClientTimeout(total=30)  # Adjust as needed
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as response:
                response.raise_for_status()
                data = await response.json()
                return data["message"]["content"].strip()
    except aiohttp.ClientResponseError as e:
        print(f"HTTP error: {e.status} - {e.message}")
        return "⚠️ Failed to generate reply (HTTP error)."
    except asyncio.TimeoutError:
        print("⏱️ Request timed out.")
        return "⚠️ Request to language model timed out."
    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return "⚠️ Failed to generate reply (unexpected error)."
