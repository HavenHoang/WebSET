import sys
import os
from PyQt6.QtWidgets import QApplication

# Add gui/ folder so payload_tab, report_tab, etc. can be imported
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
GUI_DIR = os.path.join(ROOT_DIR, "gui")
if GUI_DIR not in sys.path:
    sys.path.insert(0, GUI_DIR)

from main_window import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
