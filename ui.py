from PyQt5.QtWidgets import QMainWindow, QFileDialog, QInputDialog
from PyQt5 import uic

import crypto
from crypto import *
from crypto_classes import *


class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        self.encrypted_file = None

        uic.loadUi("application.ui", self)

        asymAlgoComboBoxValues = ["RSA", "ECC_SECP256K1"]
        self.asymAlgoComboBox.addItems(asymAlgoComboBoxValues)
        bitsComboBoxValues = map(lambda x: str(x), KEY_LENGTHS[AsymmetricAlgorithm.RSA])
        self.bitsComboBox.addItems(bitsComboBoxValues)
        self.genKeysBtn.clicked.connect(self.gen_keys_btn_clicked)
        self.saveKeysBtn.clicked.connect(self.save_keys_btn_clicked)

        symAlgoComboBoxValues = SymmetricAlgorithm.__members__
        self.symAlgoComboBox.addItems(symAlgoComboBoxValues)
        self.symAlgoComboBox.currentTextChanged.connect(self.sym_algo_combo_changed)
        symAlgoBitsComboBoxValues = []
        self.symAlgoBitsComboBox.addItems(symAlgoBitsComboBoxValues)

        self.loadPubKeyBtn.clicked.connect(self.load_pub_key_btn_clicked)
        self.loadFileToEncodeBtn.clicked.connect(self.load_file_to_encode_btn_clicked)
        self.encodeBtn.clicked.connect(self.encode_btn_clicked)
        self.saveEncodedFileBtn.clicked.connect(self.save_keys_btn_clicked)

        self.loadPrivKeyBtn.clicked.connect(self.load_priv_key_btn_clicked)
        self.loadFileToDecodeBtn.clicked.connect(self.load_file_to_decode_btn_clicked)
        self.decodeBtn.clicked.connect(self.decode_btn_clicked)

        self.loaded_encrypted_file = None
        self.encrypted_file = None
        self.loaded_file_to_encode = None

        self.show()

    def gen_keys_btn_clicked(self):
        bits = int(self.bitsComboBox.currentText())
        [pub_key, priv_key] = generate_keys(AsymmetricAlgorithm[self.asymAlgoComboBox.currentText()], bits)
        self.pubKeyTextEdit.setPlainText(pub_key.__str__())
        self.privKeyTextEdit.setPlainText(priv_key.__str__())

    def save_keys_btn_clicked(self):
        if not self.privKeyTextEdit.toPlainText():
            return
        name, ok = QInputDialog.getText(self, 'save dialog', 'Podaj nazwę kluczy:')
        if ok:
            passwd = self.pswLineEdit.text()
            if passwd == "":
                passwd = None

            saveKey(loadKeyFromStr(self.privKeyTextEdit.toPlainText(), 'private'), name, passwd)
            saveKey(loadKeyFromStr(self.pubKeyTextEdit.toPlainText(), 'public'), name)

    def sym_algo_combo_changed(self, value):
        symAlgoBitsComboBoxValues = map(lambda x: str(x), KEY_LENGTHS[SymmetricAlgorithm[value]])
        self.symAlgoBitsComboBox.clear()
        self.symAlgoBitsComboBox.addItems(symAlgoBitsComboBoxValues)

    def load_pub_key_btn_clicked(self):
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", "public\\", "key files (*.key)")
        if ok:
            file = open(filename, "r")
            pub_key = file.read()
            file.close()
            self.pubKeyTextEdit1.setPlainText(pub_key)

    def load_file_to_encode_btn_clicked(self):
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", ".", "All files (*)")
        if ok:
            with open(filename, "rb") as file:
                self.loaded_file_to_encode = file.read()

            self.fileToEncodeLineEdit.setText(self.loaded_file_to_encode[:100].decode('cp437'))

    def encode_btn_clicked(self):
        file = self.loaded_file_to_encode
        if not file:
            return
        pub_key = loadKeyFromStr(self.pubKeyTextEdit1.toPlainText(), "public")
        key_length = int(self.symAlgoBitsComboBox.currentText()) if self.symAlgoBitsComboBox.currentText() else None
        try:
            self.encrypted_file = crypto.encrypt(file,
                                                pub_key,
                                                SymmetricAlgorithm[self.symAlgoComboBox.currentText()],
                                                key_length)
            self.encodedFileLineEdit.setText(self.encrypted_file.getPrintableFile().decode("utf-8"))
        except ValueError as e:
            self.encodedFileLineEdit.setText(e.__str__())

    def save_encoded_file_btn_clicked(self):
        if self.encrypted_file is None:
            return
        filename, ok = QFileDialog.getSaveFileName(self, "Save file", '.', "All files (*)")
        if ok:
            file = open(filename, "wb")
            file.write(self.encrypted_file)
            file.close()

    def load_priv_key_btn_clicked(self):
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", "private\\", "key files (*.key)")
        if ok:
            file = open(filename, "r")
            priv_key = file.read()
            file.close()
            self.privKeyTextEdit1.setPlainText(priv_key)

    def load_file_to_decode_btn_clicked(self):
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", '', "All files (*)")
        if ok:
            file = open(filename, "rb")
            self.loaded_encrypted_file = file.read()
            file.close()
            self.fileToDecodeLineEdit.setText(self.loaded_encrypted_file.decode('cp437'))

    def decode_btn_clicked(self):
        passwd = None
        if self.loaded_encrypted_file is None:
            return
        if self.pswLineEdit1.text():
            passwd = self.pswLineEdit1.text()
        try:
            priv_key = loadKeyFromStr(self.privKeyTextEdit1.toPlainText(), "private", passwd)
            file = crypto.decrypt(self.loaded_encrypted_file, priv_key)
            self.decodedFileLineEdit.setText(file.decode("utf-8"))
        except (ValueError, TypeError) as e:
            self.decodedFileLineEdit.setText(e.__str__())
