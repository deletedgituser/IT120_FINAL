class EncryptionMiddleware:
    """
    Middleware for AES encryption and decryption.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.key = self._generate_key(b'thisisthepassword', b'hello')

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def _generate_key(self, password, salt):
        """
        Generate a secure key using PBKDF2.
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt_text(self, plain_text):
        """
        Encrypt text using AES.
        """
        import os, base64
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plain_text.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_text(self, encrypted_text):
        """
        Decrypt text using AES.
        """
        import base64
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        encrypted_bytes = base64.b64decode(encrypted_text)
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(ciphertext) + decryptor.finalize()
        return plain_text.decode('utf-8')
