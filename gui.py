import sys # Added for sys.exit
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QListWidget, QListWidgetItem, QLabel,
    QDialog, QLineEdit, QFormLayout, QMessageBox, QApplication,
    QStyle, QDialogButtonBox, QInputDialog # Added QDialogButtonBox, QInputDialog
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
    # Key is now passed during initialization after successful login
    def __init__(self, key): # Accept the key derived from master password
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 650, 450) # Adjusted size slightly
        self.key = key # Store the key

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
        # Key is already set, load passwords using it
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
         # Ensure passwords is a dictionary before iterating
         if isinstance(self.passwords, dict):
             for site in sorted(self.passwords.keys()):
                 item = QListWidgetItem(site)
                 self.password_list.addItem(item)
         else:
             # Handle case where passwords might be None or not a dict (e.g., decryption failed)
             QMessageBox.critical(self, "Load Error", "Failed to load password data correctly.")
             self.passwords = {} # Reset to empty dict

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

        # Standard Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout(self)
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.buttons)

    def get_details(self):
        """Returns the entered details as a tuple."""
        return (
            self.site_edit.text().strip(),
            self.username_edit.text().strip(),
            self.password_edit.text()
        )


# --- Setup Dialog (for initial master password and recovery email) ---
class SetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Initial Setup")
        self.setModal(True) # Ensure it blocks main window

        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter a strong master password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setPlaceholderText("Confirm master password")
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("Enter recovery email (optional but recommended)")

        form_layout = QFormLayout()
        form_layout.addRow("Master Password:", self.password_edit)
        form_layout.addRow("Confirm Password:", self.confirm_password_edit)
        form_layout.addRow("Recovery Email:", self.email_edit)

        # Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(QLabel("Welcome! Please set up your master password and recovery email."))
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.buttons)

    def get_details(self):
        password = self.password_edit.text()
        confirm_password = self.confirm_password_edit.text()
        email = self.email_edit.text().strip()
        return password, confirm_password, email

# --- Login Dialog ---
class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setModal(True)

        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter master password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout = QFormLayout()
        form_layout.addRow("Master Password:", self.password_edit)

        # Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        # Add Forgot Password button
        self.forgot_password_button = self.buttons.addButton("Forgot Password?", QDialogButtonBox.ButtonRole.ActionRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        # Connect forgot password signal in the main execution block

        main_layout = QVBoxLayout(self)
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.buttons)

    def get_password(self):
        return self.password_edit.text()

# --- Reset Password Dialog (Removed - using QInputDialog sequence now) ---
# class ResetPasswordDialog(QDialog): ...

# --- Forgot Password Handler --- (Moved outside classes)
def handle_forgot_password(parent_dialog):
    """Handles the 'Forgot Password' button click."""
    recovery_email = logic.get_recovery_email()
    if not recovery_email:
        QMessageBox.warning(parent_dialog, "No Recovery Email", "No recovery email is configured for this account. Password reset is not possible.")
        return

    confirm = QMessageBox.question(parent_dialog, "Confirm Reset",
                                   f"A password reset token will be sent to {recovery_email}. Proceed?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)

    if confirm == QMessageBox.StandardButton.Yes:
        token = logic.generate_reset_token()
        logic.store_reset_token(token) # Store hashed token and expiry
        # Simulate sending email
        if logic.send_reset_email(recovery_email, token):
            QMessageBox.information(parent_dialog, "Token Sent", f"A reset token has been sent to {recovery_email}. Check your inbox (and spam folder). It is valid for {logic.TOKEN_VALIDITY_MINUTES} minutes.")
            # Now prompt for token and new password
            prompt_for_reset_token(parent_dialog)
        else:
            QMessageBox.critical(parent_dialog, "Email Error", "Failed to send the reset token email (simulation failed). Check console/logs.")
            logic.clear_reset_token() # Clean up token if email failed

# --- Token/New Password Prompt --- (Moved outside classes)
def prompt_for_reset_token(parent_dialog):
    """Prompts the user for the reset token and new password using QInputDialog."""
    token, ok = QInputDialog.getText(parent_dialog, "Enter Reset Token", "Enter the token received via email:")
    if ok and token:
        token = token.strip()
        if logic.verify_reset_token(token):
            # Token verified, now prompt for new password
            new_password, ok_pass = QInputDialog.getText(parent_dialog, "Set New Password", "Enter your new master password:", QLineEdit.EchoMode.Password)
            if ok_pass and new_password:
                confirm_password, ok_confirm = QInputDialog.getText(parent_dialog, "Confirm New Password", "Confirm your new master password:", QLineEdit.EchoMode.Password)
                if ok_confirm and confirm_password:
                    if new_password == confirm_password:
                        try:
                            logic.set_master_password(new_password)
                            logic.clear_reset_token() # Clear token after successful reset
                            QMessageBox.information(parent_dialog, "Password Reset", "Master password has been successfully reset. The application will now close. Please restart and log in with your new password.")
                            # Optionally close the parent dialog or exit app
                            parent_dialog.reject() # Close the login dialog
                            QApplication.instance().quit() # Exit the application
                        except Exception as e:
                            QMessageBox.critical(parent_dialog, "Error", f"Failed to set new master password: {e}")
                    else:
                        QMessageBox.warning(parent_dialog, "Password Mismatch", "The new passwords do not match.")
                        # Optionally re-prompt or just fail here
                else:
                    QMessageBox.information(parent_dialog, "Cancelled", "Password reset cancelled (confirmation step).")
            else:
                QMessageBox.information(parent_dialog, "Cancelled", "Password reset cancelled (new password step).")
        else:
            QMessageBox.warning(parent_dialog, "Invalid Token", "The reset token is invalid or has expired.")
            logic.clear_reset_token() # Clear invalid/expired token
    else:
        QMessageBox.information(parent_dialog, "Cancelled", "Password reset cancelled (token entry step).")


# --- Main Execution --- (Handles Setup/Login before showing MainWindow)
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET) # Apply the stylesheet globally

    authenticated_key = None # Will store the derived key upon successful login/setup

    # --- Master Password Check and Login/Setup Flow ---
    if not logic.check_master_password_set():
        # First time setup
        setup_dialog = SetupDialog()
        while True:
            if setup_dialog.exec():
                password, confirm_password, email = setup_dialog.get_details()
                if not password or not confirm_password:
                    QMessageBox.warning(setup_dialog, "Input Error", "Master Password and Confirmation cannot be empty.")
                    continue # Re-show setup dialog
                if len(password) < 8: # Basic password strength check
                     QMessageBox.warning(setup_dialog, "Weak Password", "Master password should be at least 8 characters long.")
                     continue
                if password != confirm_password:
                    QMessageBox.warning(setup_dialog, "Password Mismatch", "The entered passwords do not match.")
                    continue # Re-show setup dialog

                # Passwords match and are not empty/weak
                try:
                    logic.set_master_password(password)
                    if email: # Store email only if provided
                        # Basic email format check (optional but good practice)
                        if '@' not in email or '.' not in email.split('@')[-1]:
                             QMessageBox.warning(setup_dialog, "Invalid Email", "Please enter a valid recovery email address or leave it blank.")
                             continue # Re-show setup dialog
                        logic.set_recovery_email(email)

                    QMessageBox.information(None, "Setup Complete", "Master password and recovery email (if provided) have been set. Please log in.")
                    # Don't authenticate yet, force login after setup
                    break # Exit setup loop, proceed to login part
                except Exception as e:
                     QMessageBox.critical(setup_dialog, "Setup Error", f"Failed to save settings: {e}")
                     continue # Re-show setup dialog if saving failed
            else:
                # User cancelled setup
                sys.exit(0) # Exit the application if setup is cancelled

    # --- Login Flow (Always runs after setup or if password was already set) ---
    login_dialog = LoginDialog()
    # Connect forgot password button signal HERE
    login_dialog.forgot_password_button.clicked.connect(lambda: handle_forgot_password(login_dialog))

    while True:
        if login_dialog.exec():
            entered_password = login_dialog.get_password()
            if logic.verify_master_password(entered_password):
                # Password correct, derive the key
                authenticated_key = logic.load_key(entered_password)
                if authenticated_key:
                    break # Exit login loop, key is ready
                else:
                    # This case should be rare if verify passed, but handle it
                    QMessageBox.critical(login_dialog, "Key Error", "Failed to derive encryption key even with correct password. Check config file.")
                    # Keep login dialog open or exit? Exit might be safer.
                    sys.exit(1)
            else:
                QMessageBox.warning(login_dialog, "Login Failed", "Incorrect master password.")
                # Keep login dialog open
        else:
            # User cancelled login
            sys.exit(0) # Exit the application if login is cancelled

    # --- Show Main Window only if authenticated key is available ---
    if authenticated_key:
        window = MainWindow(authenticated_key) # Pass the key
        window.show()
        sys.exit(app.exec())
    else:
        # Should not happen if logic above is correct, but as a safeguard
        print("Authentication failed or key derivation error. Exiting.")
        sys.exit(1)