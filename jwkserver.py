# This JWKS Server generates RSA key pairs, and serves public keys in JWKS format 
# Signed JWTs are issued for mock authentication.

from datetime import datetime, timedelta, timezone  # Standard library imports
import uuid
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request
import jwt

# KeyManager class for managing RSA key pairs
class KeyManager:

    # KeyManager class generates RSA key pairs with each key having an expired timestamp.

    def __init__(self):
        self.keys = {}

    def generate_key(self):
      
        # A Private and Public RSA key pair is generated
        # A unique kid is assigned, then stored with an expired time
        # The Key ID is returned.

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        kid = str(uuid.uuid4())
        expired = datetime.now(timezone.utc) + timedelta(days=7)

        self.keys[kid] = {
            "private_key": private_key,
            "public_key": public_key,
            "expired": expired
        }
        return kid

    def get_public_key(self, kid):
       
        # expired time associated with the kid is retrieved
        # If the kid is not found, none will be returned

        return self.keys.get(kid, {}).get("public_key", None)

    def get_expired(self, kid):
       
        # expired time associated with the kid is retrieved
        # If the kid is not found, none will be returned

        return self.keys.get(kid, {}).get("expired", None)

    def get_valid_keys(self):
       
        # All the unexpired keys are returned while the Expired keys aren't.
        
        current_time = datetime.now(timezone.utc)
        return {kid: key for kid, key in self.keys.items() if key["expired"] > current_time}

# The Flask app and KeyManager are Initialized
app = Flask(__name__)
key_manager = KeyManager()

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    
    # The Endpoint to serve public keys in a JWKS format.

    valid_keys = key_manager.get_valid_keys()
    jwks_keys = []
    
    for kid, key_info in valid_keys.items():
        public_key = key_info['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        jwks_keys.append({
            "kid": kid,
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(public_key).decode('utf-8'),
            "e": "AQAB"
        })

    return jsonify({"keys": jwks_keys})

@app.route('/auth', methods=['POST'])
def auth():
    
    # This will be the endpoint to issue signed JWTs. 
    # Any a case where an "expired" query parameter is provided, the token will be expired.
   
    expired = request.args.get('expired')
    kid = key_manager.generate_key()
    private_key = key_manager.keys[kid]["private_key"]
    
    exp_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    if expired:
        exp_time = datetime.now(timezone.utc) - timedelta(minutes=10)

    payload = {
        "sub": "user",
        "iat": datetime.now(timezone.utc),
        "exp": exp_time,
        "kid": kid
    }

    token = jwt.encode(payload, private_key, algorithm='RS256')
    return jsonify({"token": token})

if __name__ == '__main__':
    app.run(port=8080)
