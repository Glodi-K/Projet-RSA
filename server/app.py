from flask import Flask, jsonify, request
import os
import base64
import uuid
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

KEYS_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public.pem")
sessions = {}
SESSION_DURATION = 3600  # 1 heure

# Génération ou chargement des clés
def load_or_generate_keys():
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        print("Clés existantes chargées")
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

    else:
        print("Génération des clés RSA...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        # Sauvegarde
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    return private_key, public_key

def decrypt_aes(key, iv, ciphertext, tag):
    try:
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(iv, ciphertext + tag, None)
        return decrypted
    except Exception as e:
        print("Erreur AES:", str(e))
        return None

def clean_sessions():
    now = time.time()
    expired = [k for k, v in sessions.items() if v["expires"] < now]

    for k in expired:
        del sessions[k]
# Charger au démarrage
private_key, public_key = load_or_generate_keys()



@app.before_request
def security_middleware():

    if request.path in ["/", "/public-key", "/handshake"]:
        return

    session_id = request.headers.get("X-Session-ID")

    # LOG 1 : accès sans session
    if not session_id:
        print(f"[ALERTE SÉCURITÉ] Tentative d'accès non autorisé : {request.path}")
        return {"error": "Session manquante"}, 401

    session = sessions.get(session_id)

    # LOG 2 : session invalide
    if not session:
        print(f"[ALERTE SÉCURITÉ] Session invalide : {session_id}")
        return {"error": "Session invalide"}, 403

    # Nettoyage sessions expirées
    clean_sessions()

    if time.time() > session["expires"]:
        return {"error": "Session expirée"}, 403

    try:
        data = request.json

        iv = base64.b64decode(data.get("iv"))
        ciphertext = base64.b64decode(data.get("ciphertext"))
        tag = base64.b64decode(data.get("tag"))

        decrypted = decrypt_aes(session["key"], iv, ciphertext, tag)

        if decrypted is None:
            return {"error": "Échec du déchiffrement"}, 400

        request.decrypted_data = decrypted.decode()

    except Exception as e:
        print("Erreur middleware :", str(e))
        return {"error": "Charge utile chiffrée invalide"}, 400
# Endpoint clé publique
@app.route('/public-key', methods=['GET'])
def get_public_key():
    with open(PUBLIC_KEY_PATH, "r") as f:
        pem = f.read()

    return jsonify({
        "algorithm": "RSA",
        "key_size": 2048,
        "public_key": pem
    })

@app.route('/handshake', methods=['POST'])
def handshake():
    data = request.json

    client_id = data.get("client_id")
    encrypted_session_key_b64 = data.get("encrypted_session_key")

    if not client_id or not encrypted_session_key_b64:
        return {"error": "Requête invalide"}, 400

    try:
        # Décoder base64
        encrypted_session_key = base64.b64decode(encrypted_session_key_b64)

        # Déchiffrement RSA (OAEP)
        aes_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Générer session_id
        session_id = str(uuid.uuid4())

        # Stocker session
        sessions[session_id] = {
            "client_id": client_id,
            "key": aes_key,
            "expires": time.time() + SESSION_DURATION
        }

        print(f"Session créée: {session_id}")

        return {
            "status": "succès",
            "session_id": session_id,
            "expires_in": SESSION_DURATION
        }

    except Exception as e:
        print("Erreur handshake :", str(e))
        return {"error": "Échec du handshake"}, 500

@app.route('/message', methods=['POST'])
def message():
    session_id = request.headers.get("X-Session-ID")

    session = sessions.get(session_id)

    if not session:
        return {"error": "Invalid session"}, 403

    try:
        data = request.decrypted_data

        if not data:
            return {"error": "Charge utile vide"}, 400

        print(f"[MESSAGE SÉCURISÉ] {session_id} -> {data}")

        return {
            "status": "ok",
            "message_reçu": data
        }

    except Exception as e:
        print("Erreur serveur :", str(e))
        return {"error": "Échec du traitement"}, 500
    
@app.route('/')
def home():
    return "Serveur RSA en cours d'exécution"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)