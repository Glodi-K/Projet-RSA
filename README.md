# Projet RSA

Implémentation d'un système de communication sécurisée utilisant RSA et AES.

## Structure

- `server/` - Serveur Flask avec chiffrement hybride RSA/AES
- `client/` - Client Python pour communication sécurisée

## Installation

```bash
pip install flask cryptography requests
```

## Utilisation

1. Démarrer le serveur :
```bash
cd server
python app.py
```

2. Lancer le client :
```bash
cd client
python client.py
```

## Sécurité

- Chiffrement RSA 2048 bits pour l'échange de clés
- Chiffrement AES-GCM pour les messages
- Sessions avec expiration automatique
- Middleware de sécurité intégré