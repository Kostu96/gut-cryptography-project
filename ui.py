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

        symAlgoComboBoxValues = ["ChaCha20_Poly1305", "AES_GCM", "AES_CCM", "AES_SIV", "AES_CBC"]
        self.symAlgoComboBox.addItems(symAlgoComboBoxValues)
        self.symAlgoComboBox.currentTextChanged.connect(self.sym_algo_combo_changed)
        symAlgoBitsComboBoxValues = map(lambda x: str(x), KEY_LENGTHS[SymmetricAlgorithm.ChaCha20_Poly1305])
        self.symAlgoBitsComboBox.addItems(symAlgoBitsComboBoxValues)

        self.loadPubKeyBtn.clicked.connect(self.load_pub_key_btn_clicked)
        self.loadFileToEncodeBtn.clicked.connect(self.load_file_to_encode_btn_clicked)
        self.encodeBtn.clicked.connect(self.encode_btn_clicked)
        self.saveEncodedFileBtn.clicked.connect(self.save_keys_btn_clicked)

        self.loadPrivKeyBtn.clicked.connect(self.load_priv_key_btn_clicked)
        self.loadFileToDecodeBtn.clicked.connect(self.load_file_to_decode_btn_clicked)
        self.decodeBtn.clicked.connect(self.decode_btn_clicked)

        self.show()

    def gen_keys_btn_clicked(self):
        bits = int(self.bitsComboBox.currentText())
        [pub_key, priv_key] = generate_keys(AsymmetricAlgorithm[self.asymAlgoComboBox.currentText()], bits)
        self.pubKeyTextEdit.setPlainText(pub_key.__str__())
        self.privKeyTextEdit.setPlainText(priv_key.__str__())

    def save_keys_btn_clicked(self):
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
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", "c:\\", "All files (*)")
        if ok:
            file = open(filename, "r")
            str = file.read()
            file.close()
            self.fileToEncodeLineEdit.setText(str)

    def encode_btn_clicked(self):
        pub_key = loadKeyFromStr(self.pubKeyTextEdit1.toPlainText(), "public")
        file = self.fileToEncodeLineEdit.text()
        self.encrypted_file = crypto.encrypt(str.encode(file, "utf-8"),
                                             pub_key,
                                             SymmetricAlgorithm[self.symAlgoComboBox.currentText()],
                                             int(self.symAlgoBitsComboBox.currentText()))
        self.encodedFileLineEdit.setText(self.encrypted_file.getPrintableFile().decode("utf-8"))

    def save_encoded_file_btn_clicked(self):
        filename, ok = QFileDialog.getSaveFileName(self, "Save file", "c:\\", "All files (*)")
        if ok:
            file = open(filename, "wb")
            file.write(self.encrypted_file)
            file.close()

    def load_priv_key_btn_clicked(self):
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", "public\\", "key files (*.key)")
        if ok:
            file = open(filename, "r")
            priv_key = file.read()
            file.close()
            self.privKeyTextEdit1.setPlainText(priv_key)

    def load_file_to_decode_btn_clicked(self):
        filename, ok = QFileDialog.getOpenFileName(self, "Open file", "c:\\", "All files (*)")
        if ok:
            file = open(filename, "rb")
            bytes = file.read()
            file.close()
            self.encrypted_file = EncryptedFile(bytes)
            self.fileToEncodeLineEdit.setText(self.encrypted_file.getPrintableFile().decode("utf-8"))

    def decode_btn_clicked(self):
        priv_key = loadKeyFromStr(self.privKeyTextEdit1.toPlainText(), "private", self.pswLineEdit1.text())
        file = crypto.decrypt(self.encrypted_file, priv_key)
        self.decodedFileLineEdit.setText(file.decode("utf-8"))
