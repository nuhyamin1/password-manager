import os
import json
import base64
import bcrypt # Added for password hashing
import secrets # Added for secure token generation
import smtplib # Added for email sending
from email.message import EmailMessage # Added for email construction
from datetime import datetime, timedelta # Added for token expiry
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Constants ---
KEY_FILE = 'secret.key'
PASSWORD_FILE = 'passwords.enc'
CONFIG_FILE = 'config.json' # For storing master hash, email, token
TOKEN_VALIDITY_MINUTES = 15 # How long the reset token is valid

# --- Key Management ---
def generate_key(password: str, salt: bytes) -> bytes:
    """Generates a key suitable for Fernet using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000, # Increased iterations for better security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def load_key(master_password: str) -> bytes | None:
    """Loads the encryption key derived from the master password."""
    config = _load_config()
    if not config or 'master_salt' not in config:
        print("Error: Configuration or master salt not found.")
        return None
    salt = base64.urlsafe_b64decode(config['master_salt'].encode())
    return generate_key(master_password, salt)

# --- Configuration Management ---
def _load_config() -> dict:
    """Loads the configuration file (master hash, email, token)."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading config file: {e}")
        return {}

def _save_config(config: dict):
    """Saves the configuration file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        print(f"Error saving config file: {e}")

# --- Master Password Management ---
def check_master_password_set() -> bool:
    """Checks if the master password hash exists in the config."""
    config = _load_config()
    return 'master_hash' in config and config['master_hash'] is not None

def set_master_password(password: str):
    """Hashes and stores the master password, generates a new salt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    config = _load_config() # Load existing config
    config['master_hash'] = hashed_password.decode('utf-8') # Store hash as string
    config['master_salt'] = base64.urlsafe_b64encode(salt).decode('utf-8') # Store salt for key derivation
    _save_config(config)
    # Note: Setting a new master password invalidates the old encryption key.
    # Ideally, passwords should be re-encrypted, but that's complex.
    # For simplicity here, we assume the user understands this or starts fresh.
    # Clear existing encrypted passwords if the key changes fundamentally.
    if os.path.exists(PASSWORD_FILE):
        try:
            os.remove(PASSWORD_FILE)
            print("Note: Existing encrypted passwords cleared due to master password change.")
        except OSError as e:
            print(f"Warning: Could not clear old password file: {e}")

def verify_master_password(password: str) -> bool:
    """Verifies the entered master password against the stored hash."""
    config = _load_config()
    if 'master_hash' not in config:
        return False
    stored_hash = config['master_hash'].encode('utf-8')
    return bcrypt.checkpw(password.encode(), stored_hash)

# --- Recovery Email Management ---
def set_recovery_email(email: str):
    """Stores the recovery email address."""
    config = _load_config()
    config['recovery_email'] = email
    _save_config(config)

def get_recovery_email() -> str | None:
    """Retrieves the stored recovery email address."""
    config = _load_config()
    return config.get('recovery_email')

# --- Password Reset Token Management ---
def generate_reset_token() -> str:
    """Generates a secure random token."""
    return secrets.token_urlsafe(32)

def store_reset_token(token: str):
    """Stores the reset token and its expiry time."""
    config = _load_config()
    expiry_time = datetime.utcnow() + timedelta(minutes=TOKEN_VALIDITY_MINUTES)
    config['reset_token'] = {
        'token': bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode('utf-8'), # Store hashed token
        'expiry': expiry_time.isoformat()
    }
    _save_config(config)

def verify_reset_token(token: str) -> bool:
    """Verifies the provided token against the stored hash and checks expiry."""
    config = _load_config()
    token_info = config.get('reset_token')
    if not token_info or 'token' not in token_info or 'expiry' not in token_info:
        return False

    # Check expiry
    try:
        expiry_time = datetime.fromisoformat(token_info['expiry'])
        if datetime.utcnow() > expiry_time:
            print("Reset token has expired.")
            clear_reset_token() # Clear expired token
            return False
    except ValueError:
        print("Invalid token expiry format.")
        return False

    # Check token hash
    stored_token_hash = token_info['token'].encode('utf-8')
    if bcrypt.checkpw(token.encode(), stored_token_hash):
        return True
    else:
        print("Invalid reset token.")
        return False

def clear_reset_token():
    """Removes the reset token information from the config."""
    config = _load_config()
    if 'reset_token' in config:
        del config['reset_token']
        _save_config(config)
        print("Reset token cleared.")

# --- Email Sending (Simulation) ---
def send_reset_email(email_address: str, token: str) -> bool:
    """Sends the password reset email (Placeholder/Simulation)."""
    # --- !!! Real Implementation Notes !!! ---
    # 1. Get SMTP details (server, port, username, app_password) securely.
    #    NEVER hardcode credentials. Use environment variables, a secure config file
    #    (outside version control), or a secrets management system.
    #    Example using environment variables:
    #    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    #    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587)) # Default to 587 (TLS)
    #    EMAIL_SENDER = os.environ.get('EMAIL_SENDER')
    #    EMAIL_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD') # Use App Password for Gmail etc.
    #
    # 2. Check if required variables are set.
    #    if not all([SMTP_SERVER, EMAIL_SENDER, EMAIL_PASSWORD]):
    #        print("Error: Email configuration environment variables not set.")
    #        return False
    #
    # 3. Construct the EmailMessage.
    #    msg = EmailMessage()
    #    msg['Subject'] = "Password Reset Request"
    #    msg['From'] = EMAIL_SENDER
    #    msg['To'] = email_address
    #    msg.set_content(f"Your password reset token is: {token}\n\n" \
    #                    f"This token is valid for {TOKEN_VALIDITY_MINUTES} minutes.\n\n" \
    #                    f"Please enter this token in the application to reset your master password.")
    #
    # 4. Send using smtplib.
    #    try:
    #        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
    #            server.starttls() # Upgrade connection to secure
    #            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
    #            server.send_message(msg)
    #        print(f"Reset email successfully sent to {email_address}")
    #        return True
    #    except smtplib.SMTPAuthenticationError:
    #        print("Error: SMTP Authentication failed. Check sender email/password.")
    #        return False
    #    except Exception as e:
    #        print(f"Error sending email: {e}")
    #        return False
    # --- End Real Implementation Notes ---

    # --- Real Implementation --- 
    # Get SMTP details securely from environment variables
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587)) # Default to 587 (TLS)
    EMAIL_SENDER = os.environ.get('EMAIL_SENDER')
    EMAIL_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD') # Use App Password for Gmail etc.

    # Check if required variables are set
    if not all([SMTP_SERVER, EMAIL_SENDER, EMAIL_PASSWORD]):
        print("Error: Email configuration environment variables (SMTP_SERVER, SMTP_PORT, EMAIL_SENDER, EMAIL_APP_PASSWORD) not set.")
        print("INFO: Email sending skipped.")
        return False

    # Construct the EmailMessage
    msg = EmailMessage()
    msg['Subject'] = "Password Reset Request"
    msg['From'] = EMAIL_SENDER
    msg['To'] = email_address
    msg.set_content(f"Your password reset token is: {token}\n\n" \
                    f"This token is valid for {TOKEN_VALIDITY_MINUTES} minutes.\n\n" \
                    f"Please enter this token in the application to reset your master password.")

    # Send using smtplib
    try:
        # Explicitly check SMTP_SERVER is not None before using it
        if SMTP_SERVER is None:
            # This case should theoretically be caught by the 'all' check above,
            # but adding it here makes the type checker happy and adds robustness.
            print("Error: SMTP_SERVER environment variable is not set.")
            return False

        # Use SMTP_SSL for port 465, otherwise use standard SMTP with starttls
        if SMTP_PORT == 465:
             # SMTP_SERVER is now guaranteed to be str here
             with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                assert isinstance(EMAIL_SENDER, str) # Added assertion
                assert isinstance(EMAIL_PASSWORD, str) # Added assertion
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
        else: # Assume port 587 or other requires STARTTLS
            # SMTP_SERVER is now guaranteed to be str here
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls() # Upgrade connection to secure
                assert isinstance(EMAIL_SENDER, str) # Added assertion
                assert isinstance(EMAIL_PASSWORD, str) # Added assertion
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
        print(f"Reset email successfully sent to {email_address}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("Error: SMTP Authentication failed. Check sender email/app password and ensure less secure app access is handled correctly if required by your provider.")
        return False
    except smtplib.SMTPServerDisconnected:
        print("Error: Server disconnected unexpectedly. Check server address and port.")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"Error: Could not connect to SMTP server {SMTP_SERVER}:{SMTP_PORT}. Details: {e}")
        return False
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    # --- End Real Implementation ---

# --- Password Data Encryption/Decryption ---
def load_passwords(key: bytes) -> dict:
    """Loads and decrypts passwords from the file."""
    if not os.path.exists(PASSWORD_FILE):
        return {}
    try:
        with open(PASSWORD_FILE, 'rb') as f:
            encrypted_data = f.read()
        if not encrypted_data:
            return {}
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        # ValueError can be raised by Fernet for invalid key/data
        print(f"Error loading or decrypting password file: {e}")
        print("This might happen if the master password changed or the file is corrupt.")
        return {}
    except Exception as e: # Catch other potential decryption errors
        print(f"An unexpected error occurred during password loading: {e}")
        return {}

def save_passwords(passwords: dict, key: bytes):
    """Encrypts and saves passwords to the file."""
    try:
        fernet = Fernet(key)
        data_bytes = json.dumps(passwords).encode()
        encrypted_data = fernet.encrypt(data_bytes)
        with open(PASSWORD_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error encrypting or saving passwords: {e}")

# --- Utility (if needed) ---
# Example: Function to check if config/key files exist initially
def initial_setup_needed() -> bool:
    """Checks if essential files for operation exist."""
    # Simplified check: just looks for the config file with a master hash
    return not check_master_password_set()