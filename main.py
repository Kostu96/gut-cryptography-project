from PyQt5.QtWidgets import QApplication
from ui import UI


if __name__ == '__main__':
    app = QApplication([])
    mainWindow = UI()
    app.exec()
