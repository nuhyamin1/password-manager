import sys
from PyQt6.QtWidgets import QApplication, QMessageBox, QInputDialog # Added QMessageBox, QInputDialog
# Import necessary components from gui and logic
from gui import MainWindow, SetupDialog, LoginDialog, handle_forgot_password, STYLESHEET
import logic
from dotenv import load_dotenv # Add this import

load_dotenv() # Load environment variables from .env file

def main():
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
                             # Need to undo password set or handle differently? For now, just re-prompt.
                             # Ideally, validation happens before setting password.
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
    # Use the imported handle_forgot_password function
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

if __name__ == '__main__':
    main()