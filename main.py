import sys
from PyQt6.QtWidgets import QApplication
from gui import MainWindow

def main():
    app = QApplication(sys.argv)
    window = MainWindow() # Instantiate the main window
    window.show()
    # print("Password Manager Initialized - GUI to be added") # Placeholder removed
    sys.exit(app.exec())

if __name__ == '__main__':
    main()