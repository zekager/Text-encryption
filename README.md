# AES Encryption/Decryption Tool

This is a simple tool for encrypting and decrypting data using the AES (Advanced Encryption Standard) symmetric encryption algorithm. It is written in Python and uses the `cryptography` library. The application provides a graphical user interface (GUI) for easy interaction, allowing users to enter text, encrypt it, and decrypt it with a password.

## Features

- **AES-GCM Encryption**: Provides strong data encryption using the AES algorithm in GCM mode.
- **Password-Based Encryption**: Protects data with a user-provided password.
- **Salted Key Derivation**: Uses PBKDF2HMAC with SHA-256 to generate keys from passwords.
- **User-Friendly GUI**: Simple interface built using `tkinter` for easy text input and output.
- **Secure IV and Salt**: Uses a random initialization vector (IV) and salt for added security.

## Getting Started

Ensure that you have Python 3.6+ installed. You also need the following Python packages:

- `cryptography`
- `tkinter` 

For intalling write in terminal:  
pip install cryptografhy   
pip install tk  
