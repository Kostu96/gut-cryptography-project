from PyQt5.QtWidgets import QMainWindow, QPushButton
from PyQt5 import uic
from crypto import *


class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        uic.loadUi("application.ui", self)

        genKeysBtn = self.findChild(QPushButton, "genKeysBtn")
        genKeysBtn.clicked.connect(self.gen_keys_btn_clicked)

        self.bitsComboBox.addItems(["512", "1024", "2048", "4096"])

        self.show()

    def gen_keys_btn_clicked(self):
        bits = int(self.bitsComboBox.currentText())
        [pub_key, priv_key] = generate_keys(bits)
        print(pub_key, '\n', priv_key)
        self.pubKeyTextEdit.setPlainText(pub_key)
        self.privKeyTextEdit.setPlainText(priv_key)
