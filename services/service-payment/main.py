from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

app = FastAPI(title="Service Payment", version="1.0.0")

NOTIFICATION_URL = "http://service-notification:8080"

payments_db = []

class PaymentRequest(BaseModel):
    order_id: int
    amount: float
    user: str

@app.get("/health")
def health():
    return {"status": "healthy", "service": "service-payment"}

@app.post("/payment/process")
async def process_payment(req: PaymentRequest):
    payment = {
        "id": len(payments_db) + 1,
        "order_id": req.order_id,
        "amount": req.amount,
        "user": req.user,
        "status": "paid"
    }
    payments_db.append(payment)

    # Notifier service-notification
    async with httpx.AsyncClient() as client:
        try:
            await client.post(
                f"{NOTIFICATION_URL}/notify",
                json={
                    "user": req.user,
                    "message": f"Paiement de {req.amount} DT confirmé"
                }
            )
        except httpx.ConnectError:
            pass  # La notification est optionnelle

    return {"payment": payment, "message": "Paiement traité avec succès"}

@app.get("/payments")
def list_payments():
    return {"payments": payments_db}