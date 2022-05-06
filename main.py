from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow
from PyQt5.uic import loadUi


class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        loadUi("application.ui", self)
        self.show()


if __name__ == '__main__':
    app = QApplication([])
    mainWindow = UI()
    app.exec()
