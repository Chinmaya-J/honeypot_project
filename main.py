from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import re
import requests

app = FastAPI()

API_KEY = "sk_test_123456"

session_store = {}

SCAM_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended",
    "lottery", "reward", "upi", "account",
    "bank", "otp"
]

class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class RequestBody(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[dict] = {}

def detect_scam(text):
    text = text.lower()
    return any(word in text for word in SCAM_KEYWORDS)

def extract_intelligence(text, session):
    phones = re.findall(r"\+?\d{10,13}", text)
    urls = re.findall(r"https?://\S+", text)
    upi = re.findall(r"\b[\w\.-]+@[\w]+\b", text)

    session["extracted"]["phoneNumbers"].extend(phones)
    session["extracted"]["phishingLinks"].extend(urls)
    session["extracted"]["upiIds"].extend(upi)

    for word in SCAM_KEYWORDS:
        if word in text.lower():
            session["extracted"]["suspiciousKeywords"].append(word)

def send_callback(session_id, session):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["turns"],
        "extractedIntelligence": session["extracted"],
        "agentNotes": "Scammer used urgency tactics"
    }

    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
    except:
        pass

@app.post("/api/honeypot")
def honeypot(request: RequestBody, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if request.sessionId not in session_store:
        session_store[request.sessionId] = {
            "scamDetected": False,
            "turns": 0,
            "callbackSent": False,
            "extracted": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }
        }

    session = session_store[request.sessionId]
    session["turns"] += 1

    # Detect scam
    if detect_scam(request.message.text):
        session["scamDetected"] = True

    # Extract intelligence
    if request.message.sender == "scammer":
        extract_intelligence(request.message.text, session)

    # Basic agent reply
    if session["scamDetected"]:
        reply = "I am not sure. Can you explain why this is urgent?"
    else:
        reply = "Can you clarify your message?"

    # Send final callback after detection
    if session["scamDetected"] and not session["callbackSent"]:
        send_callback(request.sessionId, session)
        session["callbackSent"] = True

    return {
        "status": "success",
        "reply": reply
    }


