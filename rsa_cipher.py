import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.rsa import RSACipherUI
import requests
import rsa
import base64

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = RSACipherUI()
        self.setCentralWidget(self.ui)

        self.ui.btn_encrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btn_decrypt.clicked.connect(self.call_api_decrypt)
        self.ui.btn_generate_keys.clicked.connect(self.call_api_gen_keys)
        self.ui.btn_sign.clicked.connect(self.call_api_sign)
        self.ui.btn_verify.clicked.connect(self.call_api_verify)

    def call_api_gen_keys(self):
        url = "http://127.0.0.1:5000/api/rsa/generate_keys"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText(data["message"])
                msg.exec_()
            else:
                print("Error calling API")

        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)

    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/encrypt"
        payload = {
            "message": self.ui.txt_plain.toPlainText(),
            "key_type": "public"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_cipher.setText(data["encrypted_message"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encrypted Success")
                msg.exec_()
            else:
                print("Error calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)

    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/decrypt"
        payload = {
            "ciphertext": self.ui.txt_cipher.toPlainText(),
            "key_type": "private"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_plain.setText(data["decrypted_message"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decrypted Success")
                msg.exec_()
            else:
                print("Error calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)
    
    def call_api_sign(self):
        url = "http://127.0.0.1:5000/api/rsa/sign"
        payload = {
            "message": self.ui.txt_plain.toPlainText(),
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_signature.setText(data["signature"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Signed Success")
                msg.exec_()
            else:
                print("Error calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)

    def call_api_verify(self):
        url = "http://127.0.0.1:5000/api/rsa/verify"
        payload = {
            "message": self.ui.txt_plain.toPlainText(),
            "signature": self.ui.txt_signature.toPlainText()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if (data["is_verified"]):
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Information)
                    msg.setText("Verified Success")
                    msg.exec_()
                else:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Information)
                    msg.setText("Verified Failed")
                    msg.exec_()
            else:
                print("Error calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.setWindowTitle("RSA Client")
    window.resize(600, 480)
    window.show()
    sys.exit(app.exec_())   

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