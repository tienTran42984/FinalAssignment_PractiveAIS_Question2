import os
import rsa


class RSACipher:
    def __init__(self, key_dir="./cipher/rsa/keys"):
        self.public_key = None
        self.private_key = None
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)
    
    def generate_keys(self, key_size=1024):
        self.public_key, self.private_key = rsa.newkeys(key_size)
        self.save_keys()
        return self.public_key, self.private_key
    
    def save_keys(self, public_file="public.pem", private_file="private.pem"):
        pub_path = os.path.join(self.key_dir, public_file)
        priv_path = os.path.join(self.key_dir, private_file)

        with open(pub_path, "wb") as pub_file:
            pub_file.write(self.public_key.save_pkcs1("PEM"))

        with open(priv_path, "wb") as priv_file:
            priv_file.write(self.private_key.save_pkcs1("PEM"))

    def load_keys(self, public_file="public.pem", private_file="private.pem"):
        pub_path = os.path.join(self.key_dir, public_file)
        priv_path = os.path.join(self.key_dir, private_file)
        with open(pub_path, "rb") as pub_file:
            self.public_key = rsa.PublicKey.load_pkcs1(pub_file.read())

        with open(priv_path, "rb") as priv_file:
            self.private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

        return self.private_key, self.public_key
    
    def encrypt(self, message:str, key) -> bytes:
        message_bytes = message.encode()
        cipher_bytes = rsa.encrypt(message_bytes, key)
        return cipher_bytes
    
    def decrypt(self, cipher_bytes:bytes, key) -> str:
        message_bytes = rsa.decrypt(cipher_bytes, key)

        return message_bytes.decode()
    
    def sign(self, message:str, key) -> bytes:
        message_bytes = message.encode()
        signature_bytes = rsa.sign(message_bytes, self.private_key, "SHA-256")
        return signature_bytes
    
    def verify(self, message:str, signature_bytes:bytes, key) -> bool:
        message_bytes = message.encode()
        try:
            rsa.verify(message_bytes, signature_bytes, key)
            return True
        except rsa.VerificationError:
            return False 