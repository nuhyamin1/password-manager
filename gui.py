import sys # Added for sys.exit
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QListWidget, QListWidgetItem, QLabel,
    QDialog, QLineEdit, QFormLayout, QMessageBox, QApplication,
    QStyle # Added QStyle import
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon # Added for icons
import logic # Import the logic module

# --- Stylesheet Definition ---
STYLESHEET = """
QMainWindow {
    background-color: #f0f0f0; /* Light gray background */
}

QPushButton {
    background-color: #007bff; /* Primary blue */
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-size: 10pt;
    min-width: 80px; /* Ensure buttons have a minimum width */
}

QPushButton:hover {
    background-color: #0056b3; /* Darker blue on hover */
}

QPushButton:pressed {
    background-color: #004085; /* Even darker blue when pressed */
}

/* Style delete button differently */
QPushButton#deleteButton { /* Use object name for specific styling */
    background-color: #dc3545; /* Red */
}
QPushButton#deleteButton:hover {
    background-color: #c82333; /* Darker red */
}
QPushButton#deleteButton:pressed {
    background-color: #bd2130; /* Even darker red */
}


QListWidget {
    border: 1px solid #ced4da; /* Light gray border */
    border-radius: 4px;
    background-color: white;
    font-size: 10pt;
    padding: 5px;
}

QListWidget::item {
    padding: 5px; /* Add padding to list items */
}


QListWidget::item:selected {
    background-color: #007bff; /* Blue selection */
    color: white;
}

QLabel {
    font-size: 11pt;
    font-weight: bold;
    margin-bottom: 5px;
    color: #333; /* Darker text color */
}

QLineEdit {
    padding: 6px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 10pt;
}

QLineEdit:focus {
    border-color: #80bdff; /* Highlight focus */
}


QDialog {
    background-color: #f8f9fa; /* Slightly different background for dialogs */
}

/* Style dialog buttons */
QDialog QPushButton {
    padding: 6px 12px;
    min-width: 70px;
}

QMessageBox {
    font-size: 10pt;
}
/* Add some spacing */
QVBoxLayout, QHBoxLayout, QFormLayout {
    spacing: 10px; /* Add space between widgets in layouts */
}
QWidget { /* Add margin around the central widget */
    margin: 10px;
}

"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 650, 450) # Adjusted size slightly

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget) # Apply layout directly to widget

        # --- Widgets ---
        self.password_list = QListWidget()
        self.add_button = QPushButton(" Add") # Add space for icon
        self.edit_button = QPushButton(" Edit")
        self.delete_button = QPushButton(" Delete")
        self.copy_button = QPushButton(" Copy")

        # --- Set Object Names for Specific Styling ---
        self.delete_button.setObjectName("deleteButton")

        # --- Add Icons ---
        style = QApplication.style()
        self.add_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder)) # Example icon
        self.edit_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)) # Example icon
        self.delete_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_TrashIcon))
        self.copy_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)) # Example icon (copy often uses 'save' appearance)


        # --- Layouts ---
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.edit_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addStretch() # Add stretch to push copy button to the right
        button_layout.addWidget(self.copy_button)

        layout.addWidget(QLabel("Stored Passwords:"))
        layout.addWidget(self.password_list)
        layout.addLayout(button_layout)

        # --- Load Initial Data ---
        self.key = logic.load_key()
        self.passwords = logic.load_passwords(self.key)
        self.refresh_password_list()

        # --- Connect Signals ---
        self.add_button.clicked.connect(self.add_password_dialog)
        self.edit_button.clicked.connect(self.edit_password_dialog)
        self.delete_button.clicked.connect(self.delete_password)
        self.copy_button.clicked.connect(self.copy_password)
        self.password_list.itemDoubleClicked.connect(self.edit_password_dialog) # Allow double-click to edit
 
    def refresh_password_list(self):
         """Clears and repopulates the password list widget."""
         self.password_list.clear()
         for site in sorted(self.passwords.keys()):
             item = QListWidgetItem(site)
             self.password_list.addItem(item)
 
     # --- Button Action Implementations ---
    def add_password_dialog(self):
         """Opens a dialog to add a new password entry."""
         dialog = PasswordDialog(self)
         if dialog.exec(): # Show the dialog modally, returns true if accepted
             site, username, password = dialog.get_details()
             if site and username and password: # Ensure all fields are filled
                 if site in self.passwords:
                     QMessageBox.warning(self, "Duplicate Site", f"An entry for '{site}' already exists.")
                     return
                 self.passwords[site] = {'username': username, 'password': password}
                 logic.save_passwords(self.passwords, self.key)
                 self.refresh_password_list()
             else:
                 QMessageBox.warning(self, "Missing Information", "Please fill in all fields (Site, Username, Password).")

    def edit_password_dialog(self):
         """Opens a dialog to edit the selected password entry."""
         selected_item = self.password_list.currentItem()
         if not selected_item:
             QMessageBox.warning(self, "Selection Required", "Please select a password entry to edit.")
             return

         site = selected_item.text()
         if site not in self.passwords:
             QMessageBox.critical(self, "Error", f"Could not find data for '{site}'.") # Should not happen
             return

         current_details = self.passwords[site]
         dialog = PasswordDialog(self, site=site, username=current_details['username'], password=current_details['password'])
         # Make site field read-only during edit
         dialog.site_edit.setReadOnly(True)

         if dialog.exec():
             new_site, new_username, new_password = dialog.get_details()
             # Site shouldn't change, but check username/password
             if new_username and new_password:
                 self.passwords[site] = {'username': new_username, 'password': new_password}
                 logic.save_passwords(self.passwords, self.key)
                 self.refresh_password_list() # Refresh list to show potential changes (though site name doesn't change here)
                 # Re-select the edited item for better UX
                 items = self.password_list.findItems(site, Qt.MatchFlag.MatchExactly)
                 if items:
                     self.password_list.setCurrentItem(items[0])
             else:
                 QMessageBox.warning(self, "Missing Information", "Please fill in Username and Password fields.")
 
    def delete_password(self):
         """Deletes the selected password entry after confirmation."""
         selected_item = self.password_list.currentItem()
         if not selected_item:
             QMessageBox.warning(self, "Selection Required", "Please select a password entry to delete.")
             return

         site = selected_item.text()
         reply = QMessageBox.question(self, 'Confirm Delete',
                                      f"Are you sure you want to delete the password for '{site}'?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No) # Default to No

         if reply == QMessageBox.StandardButton.Yes:
             if site in self.passwords:
                 del self.passwords[site]
                 logic.save_passwords(self.passwords, self.key)
                 self.refresh_password_list()
             else:
                 QMessageBox.critical(self, "Error", f"Could not find data for '{site}' to delete.") # Should not happen
 
    def copy_password(self):
         """Copies the password of the selected entry to the clipboard."""
         selected_item = self.password_list.currentItem()
         if not selected_item:
             QMessageBox.warning(self, "Selection Required", "Please select a password entry to copy.")
             return

         site = selected_item.text()
         if site in self.passwords:
             password_to_copy = self.passwords[site]['password']
             clipboard = QApplication.clipboard()
             if clipboard: # Add check for None
                 clipboard.setText(password_to_copy)
                 # Use QMessageBox for feedback as status bar might not be visible/styled yet
                 QMessageBox.information(self, "Copied", f"Password for '{site}' copied to clipboard.")
             else:
                 QMessageBox.warning(self, "Clipboard Error", "Could not access the system clipboard.")
         else:
             QMessageBox.critical(self, "Error", f"Could not find password data for '{site}'.") # Should not happen

# --- Add/Edit Dialog ---
class PasswordDialog(QDialog):
    def __init__(self, parent=None, site="", username="", password=""):
        super().__init__(parent)
        self.setWindowTitle("Add/Edit Password")

        self.site_edit = QLineEdit(site)
        self.username_edit = QLineEdit(username)
        self.password_edit = QLineEdit(password)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password) # Mask password

        form_layout = QFormLayout()
        form_layout.addRow("Site:", self.site_edit)
        form_layout.addRow("Username:", self.username_edit)
        form_layout.addRow("Password:", self.password_edit)

        # Buttons
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        main_layout = QVBoxLayout(self) # Apply layout directly
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)
        # self.setLayout(main_layout) # No longer needed

        # Connect signals
        self.ok_button.clicked.connect(self.accept) # Built-in accept slot
        self.cancel_button.clicked.connect(self.reject) # Built-in reject slot

    def get_details(self):
        """Returns the entered details as a tuple."""
        return (
            self.site_edit.text().strip(),
            self.username_edit.text().strip(),
            self.password_edit.text()
        )


# --- Main Execution ---
# This part should be in your main script file (e.g., main.py or at the end of gui.py if it's standalone)
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET) # Apply the stylesheet globally

    window = MainWindow()
    window.show()

    sys.exit(app.exec())