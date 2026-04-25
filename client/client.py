import requests
import json
import base64
import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URL = "http://rsa-server:5000"

def get_public_key():
    res = requests.get(f"{SERVER_URL}/public-key")
    data = res.json()

    public_key = serialization.load_pem_public_key(
        data["public_key"].encode()
    )

    return public_key

def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)

def encrypt_aes_key(public_key, aes_key):
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted).decode()

def handshake(client_id, encrypted_key):
    res = requests.post(f"{SERVER_URL}/handshake", json={
        "client_id": client_id,
        "encrypted_session_key": encrypted_key
    })

    return res.json()

def encrypt_message(aes_key, message):
    aesgcm = AESGCM(aes_key)

    iv = os.urandom(12)

    ciphertext = aesgcm.encrypt(iv, message.encode(), None)

    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext[:-16]).decode(),
        "tag": base64.b64encode(ciphertext[-16:]).decode()
    }

def send_message(session_id, encrypted_payload):
    res = requests.post(
        f"{SERVER_URL}/message",
        json=encrypted_payload,
        headers={"X-Session-ID": session_id}
    )

    return res.json()

def main():
    client_id = str(uuid.uuid4())

    print("1. Récupération clé publique...")
    public_key = get_public_key()

    print("2. Génération AES...")
    aes_key = generate_aes_key()

    print("3. Chiffrement AES avec RSA...")
    encrypted_key = encrypt_aes_key(public_key, aes_key)

    print("4. Handshake...")
    response = handshake(client_id, encrypted_key)

    session_id = response.get("session_id")
    print("Session :", session_id)

    print("5. Envoi message chiffré...")

    encrypted_payload = encrypt_message(aes_key, " Voici le message sécurisé")

    response = send_message(session_id, encrypted_payload)

    print("Réponse serveur :", response)


if __name__ == "__main__":
    main()

