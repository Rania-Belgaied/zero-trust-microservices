import requests
import json
import sys

KEYCLOAK_URL = "http://localhost:8080"
ADMIN_USER   = "admin"
ADMIN_PASS   = "admin-zero-trust-2026"
REALM_NAME   = "zero-trust-project"

def get_admin_token():
    print("Obtention du token admin...")
    resp = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id":  "admin-cli",
            "username":   ADMIN_USER,
            "password":   ADMIN_PASS,
        }
    )
    if resp.status_code != 200:
        print(f"Erreur token admin: {resp.text}")
        sys.exit(1)
    print("Token admin obtenu")
    return resp.json()["access_token"]

def create_realm(token):
    print(f"Création du realm '{REALM_NAME}'...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }
    realm_config = {
        "realm":               REALM_NAME,
        "enabled":             True,
        "displayName":         "Zero Trust Project",
        "accessTokenLifespan": 300,  # 5 minutes
    }
    resp = requests.post(
        f"{KEYCLOAK_URL}/admin/realms",
        headers=headers,
        json=realm_config
    )
    if resp.status_code == 201:
        print(f"Realm '{REALM_NAME}' créé avec succès")
    elif resp.status_code == 409:
        print(f"Realm '{REALM_NAME}' existe déjà")
    else:
        print(f"Erreur création realm: {resp.status_code} - {resp.text}")
        sys.exit(1)

def create_client(token, client_id, client_name, client_secret):
    print(f"Création du client '{client_id}'...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }
    client_config = {
        "clientId":               client_id,
        "name":                   client_name,
        "enabled":                True,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled":    False,
        "directAccessGrantsEnabled": False,
        "secret":                 client_secret,
    }
    resp = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients",
        headers=headers,
        json=client_config
    )
    if resp.status_code == 201:
        print(f"Client '{client_id}' créé avec succès")
    elif resp.status_code == 409:
        print(f"Client '{client_id}' existe déjà")
    else:
        print(f"Erreur création client {client_id}: {resp.status_code} - {resp.text}")

if __name__ == "__main__":
    token = get_admin_token()
    create_realm(token)

    services = [
        ("service-auth",         "Service Auth",         "service-auth-secret-2026"),
        ("service-orders",       "Service Orders",       "service-orders-secret-2026"),
        ("service-payment",      "Service Payment",      "service-payment-secret-2026"),
        ("service-notification", "Service Notification", "service-notification-secret-2026"),
        ("lsa-agent",            "LSA Security Agent",   "lsa-agent-secret-2026"),
    ]

    for client_id, name, secret in services:
        create_client(token, client_id, name, secret)

    print("\nConfiguration Keycloak terminée !")
    print(f"Realm    : {REALM_NAME}")
    print(f"Admin URL: {KEYCLOAK_URL}/admin")