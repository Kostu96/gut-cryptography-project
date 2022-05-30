from PyQt5.QtWidgets import QMainWindow, QFileDialog
from PyQt5 import uic

import crypto
from crypto import *
from crypto_classes import *


class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        uic.loadUi("application.ui", self)

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

        self.decodeBtn.clicked.connect(self.decode_btn_clicked)

        self.show()

    def gen_keys_btn_clicked(self):
        bits = int(self.bitsComboBox.currentText())
        [pub_key, priv_key] = generate_keys(AsymmetricAlgorithm.RSA, bits)
        self.pubKeyTextEdit.setPlainText(pub_key.__str__())
        self.privKeyTextEdit.setPlainText(priv_key.__str__())

    def save_keys_btn_clicked(self):
        dir = QFileDialog.getExistingDirectory(self, 'Open file', 'c:\\')
        f_priv = open(dir + "/private.txt", "w")
        f_priv.write(self.privKeyTextEdit.toPlainText())
        f_priv.close()
        f_pub = open(dir + "/public.txt", "w")
        f_pub.write(self.pubKeyTextEdit.toPlainText())
        f_pub.close()

    def sym_algo_combo_changed(self, value):
        symAlgoBitsComboBoxValues = map(lambda x: str(x), KEY_LENGTHS[SymmetricAlgorithm[value]])
        self.symAlgoBitsComboBox.clear()
        self.symAlgoBitsComboBox.addItems(symAlgoBitsComboBoxValues)

    def load_pub_key_btn_clicked(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open file", "c:\\", "Text files (*.txt)")
        file = open(filename, "r")
        pub_key = file.read()
        file.close()
        self.pubKeyTextEdit1.setPlainText(pub_key)

    def load_file_to_encode_btn_clicked(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open file", "c:\\", "All files (*)")
        file = open(filename, "r")
        str = file.read()
        file.close()
        self.fileToEncodeLineEdit.setText(str)
        pass

    def encode_btn_clicked(self):
        pub_key = loadKeyFromStr(self.pubKeyTextEdit1.toPlainText(), "public")
        file = self.fileToEncodeLineEdit.text()
        encrypted_file = crypto.encrypt(str.encode(file, "utf-8"),
                                        pub_key,
                                        SymmetricAlgorithm[self.symAlgoComboBox.currentText()],
                                        int(self.symAlgoBitsComboBox.currentText()))
        self.encodedFileLineEdit.setText(encrypted_file.getPrintableFile().decode("utf-8"))

    def save_encoded_file_btn_clicked(self):
        pass

    def decode_btn_clicked(self):
        pass
