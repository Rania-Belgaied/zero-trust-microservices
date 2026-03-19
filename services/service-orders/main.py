from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

app = FastAPI(title="Service Orders", version="1.0.0")

AUTH_URL = "http://service-auth:8080"
PAYMENT_URL = "http://service-payment:8080"

orders_db = []

class OrderRequest(BaseModel):
    user_token: str
    product: str
    amount: float

@app.get("/health")
def health():
    return {"status": "healthy", "service": "service-orders"}

@app.post("/orders/create")
async def create_order(req: OrderRequest):
    # Valider le token auprès de service-auth
    async with httpx.AsyncClient() as client:
        try:
            auth_resp = await client.get(
                f"{AUTH_URL}/auth/validate",
                params={"token": req.user_token}
            )
            if auth_resp.status_code != 200:
                raise HTTPException(status_code=401, detail="Token invalide")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Service auth indisponible")

    order = {
        "id": len(orders_db) + 1,
        "product": req.product,
        "amount": req.amount,
        "status": "created"
    }
    orders_db.append(order)
    return {"order": order, "message": "Commande créée avec succès"}

@app.get("/orders")
def list_orders():
    return {"orders": orders_db}