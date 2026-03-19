from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Service Notification", version="1.0.0")

notifications_db = []

class NotificationRequest(BaseModel):
    user: str
    message: str


@app.get("/health")
def health():
    return {"status": "healthy", "service": "service-notification"}

@app.post("/notify")
def send_notification(req: NotificationRequest):
    notif = {
        "id": len(notifications_db) + 1,
        "user": req.user,
        "message": req.message,
        "sent": True
    }
    notifications_db.append(notif)
    print(f"[NOTIFICATION] → {req.user} : {req.message}")
    return {"notification": notif, "message": "Notification envoyée"}

@app.get("/notifications")
def list_notifications():
    return {"notifications": notifications_db}