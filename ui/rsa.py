from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QPushButton, QGridLayout
)
import sys

class RSACipherUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RSA Cipher")
        self.setGeometry(200, 200, 900, 350)

        grid = QGridLayout()

        # ---------------- LEFT SIDE ----------------
        lbl_plain = QLabel("Plain Text:")
        self.txt_plain = QTextEdit()

        lbl_cipher = QLabel("CipherText:")
        self.txt_cipher = QTextEdit()

        # Buttons under left boxes
        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_decrypt = QPushButton("Decrypt")

        # ---------------- RIGHT SIDE ----------------
        # lbl_info = QLabel("Information:")
        # self.txt_info = QTextEdit()

        lbl_sign = QLabel("Signature:")
        self.txt_signature = QTextEdit()

        # Buttons under right boxes
        self.btn_sign = QPushButton("Sign")
        self.btn_verify = QPushButton("Verify")

        # Top right button
        self.btn_generate_keys = QPushButton("Generate Keys")

        # ---------------- ADD WIDGETS TO GRID ----------------

        # Top title row (generate key at top right)
        grid.addWidget(QLabel("<h2>RSA CIPHER</h2>"), 0, 0)
        grid.addWidget(self.btn_generate_keys, 0, 1)

        # Left side
        grid.addWidget(lbl_plain, 1, 0)
        grid.addWidget(self.txt_plain, 2, 0, 1, 2)

        grid.addWidget(lbl_cipher, 3, 0)
        grid.addWidget(self.txt_cipher, 4, 0)

        grid.addWidget(self.btn_encrypt, 5, 0)
        grid.addWidget(self.btn_decrypt, 6, 0)

        # # Right side
        # grid.addWidget(lbl_info, 1, 1)
        # grid.addWidget(self.txt_info, 2, 1)

        grid.addWidget(lbl_sign, 3, 1)
        grid.addWidget(self.txt_signature, 4, 1)

        grid.addWidget(self.btn_sign, 5, 1)
        grid.addWidget(self.btn_verify, 6, 1)

        self.setLayout(grid)


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = RSACipherUI()
    ui.show()
    sys.exit(app.exec())