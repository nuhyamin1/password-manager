from cryptography.fernet import Fernet
import os
import json

# --- Constants ---
KEY_FILE = 'secret.key'
DATA_FILE = 'passwords.enc'

# --- Key Management ---
def generate_key():
    """Generates a new encryption key and saves it to KEY_FILE."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    """Loads the encryption key from KEY_FILE. Generates a new one if it doesn't exist."""
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key

# --- Encryption/Decryption ---
def encrypt_data(data, key):
    """Encrypts data using the provided key."""
    f = Fernet(key)
    # Convert data (dict) to JSON string, then encode to bytes
    data_bytes = json.dumps(data).encode('utf-8')
    encrypted_data = f.encrypt(data_bytes)
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Decrypts data using the provided key."""
    f = Fernet(key)
    try:
        decrypted_bytes = f.decrypt(encrypted_data)
        # Decode bytes to JSON string, then parse to dict
        data = json.loads(decrypted_bytes.decode('utf-8'))
        return data
    except Exception as e:
        print(f"Decryption failed: {e}") # Handle potential errors (e.g., wrong key)
        return None

# --- Password Data Management ---
def load_passwords(key):
    """Loads and decrypts passwords from DATA_FILE."""
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as file:
        encrypted_data = file.read()
    
    # Handle case where file is empty
    if not encrypted_data:
        return {}
        
    passwords = decrypt_data(encrypted_data, key)
    return passwords if passwords is not None else {}

def save_passwords(passwords, key):
    """Encrypts and saves passwords to DATA_FILE."""
    encrypted_data = encrypt_data(passwords, key)
    with open(DATA_FILE, 'wb') as file:
        file.write(encrypted_data)

# --- Core Logic Placeholder ---
# Functions to add/edit/delete passwords will go here
# These will interact with the loaded password dictionary

# Example usage (for testing, remove later)
if __name__ == '__main__':
    my_key = load_key()
    print(f"Key loaded/generated: {my_key}")

    # Initial load (or create empty)
    my_passwords = load_passwords(my_key)
    print(f"Initial passwords: {my_passwords}")

    # Add a password (example)
    my_passwords['example.com'] = {'username': 'testuser', 'password': 'secretpassword123'}
    print(f"Passwords after adding: {my_passwords}")

    # Save changes
    save_passwords(my_passwords, my_key)
    print("Passwords saved.")

    # Reload to verify
    reloaded_passwords = load_passwords(my_key)
    print(f"Reloaded passwords: {reloaded_passwords}")