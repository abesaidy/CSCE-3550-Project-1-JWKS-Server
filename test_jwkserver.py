import unittest
from datetime import datetime, timezone  
import jwt
from jwkserver import app, KeyManager

class JWKSAuthTest(unittest.TestCase):
    """Test class for the JWKS Server's endpoints and key management."""

    def setUp(self):
        """Set up the Flask test client and key manager."""
        self.app = app.test_client()
        self.app.testing = True
        self.key_manager = KeyManager()

    def test_key_generation(self):
        """Test if the key generation works and returns a valid key ID."""
        kid = self.key_manager.generate_key()
        self.assertIsNotNone(kid, "The key ID should not be None.")
        public_key = self.key_manager.get_public_key(kid)
        self.assertIsNotNone(public_key, "The public key should not be None.")
        expiry = self.key_manager.get_expiry(kid)
        self.assertIsNotNone(expiry, "The expiry time should not be None.")

    def test_jwks_endpoint(self):
        """Test if the JWKS endpoint returns valid public keys in JWKS format."""
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200, "JWKS endpoint should return status code 200.")
        jwks = response.get_json()
        self.assertIn("keys", jwks, "JWKS response should contain 'keys'.")
        if len(jwks["keys"]) > 0:
            first_key = jwks["keys"][0]
            self.assertIn("kid", first_key, "Each key in JWKS should have a 'kid'.")
            self.assertIn("kty", first_key, "Each key in JWKS should have a 'kty'.")
            self.assertIn("alg", first_key, "Each key in JWKS should have an 'alg'.")

    def test_auth_endpoint(self):
        """Test if the /auth endpoint issues a valid JWT."""
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200, "Auth endpoint should return status code 200.")
        data = response.get_json()
        self.assertIn("token", data, "The response should contain a JWT token.")
        token = data["token"]
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        self.assertIn("kid", decoded_token, "The JWT token should include 'kid' in its header.")
        self.assertIn("sub", decoded_token, "The JWT token should contain 'sub' in the payload.")

    def test_expired_auth(self):
        """Test if the /auth?expired=true endpoint issues an expired JWT."""
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200, "Auth endpoint should return status code 200.")
        data = response.get_json()
        self.assertIn("token", data, "The response should contain a JWT token.")
        token = data["token"]
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        self.assertIn("kid", decoded_token, "'kid' should've been included in the header for the JWT token.")
        self.assertIn("sub", decoded_token, "'sub' should've been contained in the payload for the JWT token.")
        self.assertIn("exp", decoded_token, "An 'exp' claim should've been in the JWT token.")
        self.assertTrue(decoded_token["exp"] < int(datetime.now(timezone.utc).timestamp()), "The JWT token should be expired.")

if __name__ == '__main__':
    unittest.main()

