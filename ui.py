from PyQt5.QtWidgets import QMainWindow
from PyQt5 import uic
from crypto import *


class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        uic.loadUi("application.ui", self)

        self.bitsComboBox.addItems(["512", "1024", "2048", "4096"])
        self.genKeysBtn.clicked.connect(self.gen_keys_btn_clicked)
        self.encodeBtn.clicked.connect(self.encode_btn_clicked)
        self.decodeBtn.clicked.connect(self.decode_btn_clicked)

        self.show()

    def gen_keys_btn_clicked(self):
        bits = int(self.bitsComboBox.currentText())
        [pub_key, priv_key] = generate_keys(AsymmetricAlgorithm.RSA, bits)
        self.pubKeyTextEdit.setPlainText(pub_key.__str__())
        self.privKeyTextEdit.setPlainText(priv_key.__str__())

    def encode_btn_clicked(self):
        pass

    def decode_btn_clicked(self):
        pass
