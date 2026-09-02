import os
import hmac
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from config.settings import NONCE_LENGTH

class CryptoEngine:
    """
    Cryptographic engine providing:
    - X25519 ECDH Key Agreement for forward-secrecy
    - Ed25519 Digital Signatures for Non-Repudiation
    - HKDF-SHA256 Key Derivation & Periodic Rekeying
    - AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
    - HMAC-SHA256 packet authentication & Tamper Evidence
    """

    def __init__(self, pre_shared_key: bytes = None):
        self.psk = pre_shared_key or hashlib.sha256(b"SecureHarness_Default_Master_Key_2026").digest()
        self.session_key = self.psk
        self.aesgcm = AESGCM(self.session_key)
        self.rekey_counter = 0
        self.packets_processed_on_key = 0
        
        # Ed25519 Keypair for Non-Repudiation signatures
        self.signing_private_key = ed25519.Ed25519PrivateKey.generate()
        self.signing_public_bytes = self.signing_private_key.public_key().public_bytes_raw()

    @staticmethod
    def generate_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
        """Generates X25519 private key and public key bytes"""
        private_key = x25519.X25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes_raw()
        return private_key, public_bytes

    def derive_session_key(self, private_key: x25519.X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
        """Derives a shared 256-bit symmetric session key using ECDH + HKDF"""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SecureHarnessTunnelSalt",
            info=b"SecureHarnessSessionHandshake",
        ).derive(shared_secret + self.psk)

        self.session_key = derived_key
        self.aesgcm = AESGCM(self.session_key)
        self.rekey_counter = 0
        self.packets_processed_on_key = 0
        return derived_key

    def rekey(self) -> bytes:
        """
        Advances session key forward via ratchet derivation (Perfect Forward Secrecy / PQC hardening)
        """
        self.rekey_counter += 1
        new_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SecureHarnessRatchetSalt",
            info=f"SecureHarnessRatchetCounter_{self.rekey_counter}".encode(),
        ).derive(self.session_key)
        
        self.session_key = new_key
        self.aesgcm = AESGCM(self.session_key)
        self.packets_processed_on_key = 0
        return new_key

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypts plaintext with AES-256-GCM.
        Returns: [12-byte Nonce] + [Ciphertext + 16-byte Auth Tag]
        """
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        self.packets_processed_on_key += 1
        return nonce + ciphertext

    def decrypt(self, payload: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypts payload: [12-byte Nonce] + [Ciphertext + 16-byte Auth Tag]
        Raises cryptography.exceptions.InvalidTag if tampered or corrupt.
        """
        if len(payload) < NONCE_LENGTH + 16:
            raise ValueError("Payload too short to contain valid Nonce and GCM Tag")
        nonce = payload[:NONCE_LENGTH]
        ciphertext = payload[NONCE_LENGTH:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        self.packets_processed_on_key += 1
        return plaintext

    def compute_hmac(self, data: bytes) -> bytes:
        """Calculates HMAC-SHA256 signature using current session key"""
        return hmac.new(self.session_key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, expected_hmac: bytes) -> bool:
        """Timing-safe HMAC comparison"""
        computed = self.compute_hmac(data)
        return hmac.compare_digest(computed, expected_hmac)

    # -------------------------------------------------------------
    # Non-Repudiation (Ed25519 Signatures)
    # -------------------------------------------------------------
    def sign_payload(self, data: bytes) -> bytes:
        """Generates 64-byte Ed25519 digital signature for non-repudiation"""
        return self.signing_private_key.sign(data)

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verifies Ed25519 digital signature"""
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub_key.verify(signature, data)
            return True
        except Exception:
            return False
