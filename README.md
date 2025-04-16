# Password Manager

A simple desktop application built with Python and PyQt6 for securely storing and managing your passwords.

## Description

This application provides a graphical user interface (GUI) to add, edit, delete, and copy passwords for different websites or services. It uses the `cryptography` library to encrypt your passwords, ensuring they are stored securely on your local machine.

## Features

*   **Add Passwords:** Easily add new entries with site name, username, and password.
*   **Edit Passwords:** Modify existing usernames and passwords (site name is fixed after creation).
*   **Delete Passwords:** Remove entries you no longer need.
*   **Copy Password:** Quickly copy the password for a selected site to your clipboard.
*   **Secure Storage:** Passwords are encrypted using Fernet symmetric encryption (`cryptography` library) before being saved to a local file (`passwords.enc`).
*   **Automatic Key Generation:** An encryption key (`secret.key`) is automatically generated on the first run if one doesn't exist.

## Requirements

*   Python 3.x
*   PyQt6
*   cryptography

## Installation

1.  **Clone the repository (or download the source code):**
    ```bash
    git clone <repository-url> # Replace with the actual URL if applicable
    cd Password-Manager
    ```
2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```
3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the main application file from the project's root directory:

```bash
python main.py
```

On the first launch, the application will create a `secret.key` file in the same directory. This key is crucial for encrypting and decrypting your passwords.

## Security

*   **Encryption:** Your passwords are encrypted using the Fernet algorithm provided by the `cryptography` library. The encrypted data is stored in the `passwords.enc` file.
*   **Key Management:** The encryption key is stored in the `secret.key` file. **It is vital to keep this file secure and private.** Anyone with access to this key file can potentially decrypt your passwords stored in `passwords.enc`.
*   **Do not share your `secret.key` file.**
*   Consider backing up your `secret.key` and `passwords.enc` files securely.
*   The `.gitignore` file is configured to prevent accidentally committing the `secret.key` and `passwords.enc` files to a Git repository.