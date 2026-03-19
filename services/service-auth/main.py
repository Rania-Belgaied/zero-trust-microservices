from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Service Auth", version="1.0.0")

USERS_DB = {
    "alice": {"password": "secret", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}

class LoginRequest(BaseModel):
    username: str 
    password: str 

@app.get("/health")
def health():
    return {"status": "healthy", "service": "service-auth"}


@app.post("/auth/login")
def lgin(req: LoginRequest):
    user = USERS_DB.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Credentials invalides")
    return {"token": f"demo-token-{req.username}", "role": user["role"]}


@app.get("/auth/validate")
def validate(token: str):
    if token.startswith("demo-token-"):
        username = token.replace("demo-token-", "")
        return {"valid": True, "username": username}
    raise HTTPException(status_code=401, detail="Token invalide")