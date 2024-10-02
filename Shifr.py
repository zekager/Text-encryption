import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class AESCipher:
    def __init__(self, password: str, iterations: int = 100000):
        self.password = password.encode()
        self.iterations = iterations

    def _generate_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode('utf-8')  
        salt = os.urandom(16)  
        iv = os.urandom(12)
        key = self._generate_key(salt)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return base64.b64encode(salt + iv + encryptor.tag + ciphertext).decode()

    def decrypt(self, encrypted_data: str) -> str:
        encrypted_data = base64.b64decode(encrypted_data)  
        salt = encrypted_data[:16]  
        iv = encrypted_data[16:28]  
        tag = encrypted_data[28:44]  
        ciphertext = encrypted_data[44:]  
        key = self._generate_key(salt)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_message():
    plaintext = text_input.get("1.0", tk.END).strip()
    password = password_input.get().strip()
    
    if not plaintext or not password:
        messagebox.showerror("Помилка", "Введіть текст і пароль для шифрування!")
        return

    aes_cipher = AESCipher(password)
    encrypted_message = aes_cipher.encrypt(plaintext)
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, encrypted_message)

def decrypt_message():
    encrypted_text = text_input.get("1.0", tk.END).strip()
    password = password_input.get().strip()
    
    if not encrypted_text or not password:
        messagebox.showerror("Помилка", "Введіть зашифрований текст і пароль для дешифрування!")
        return
    
    try:
        aes_cipher = AESCipher(password)
        decrypted_message = aes_cipher.decrypt(encrypted_text)
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, decrypted_message.decode('utf-8'))  # Декодуємо байти в текст
    except Exception as e:
        messagebox.showerror("Помилка", f"Неможливо розшифрувати текст: {str(e)}")

root = tk.Tk()
root.title("AES Шифрування/Дешифрування")
root.geometry("600x600")  
root.config(bg="#B7C9A3")  

icon= tk.PhotoImage(file="Untitled.png")
root.iconphoto(False, icon)

tk.Label(root, text="Введіть текст:", bg="#f0f0f0", font=("Arial", 12)).pack(pady=10)
text_input = tk.Text(root, height=10, width=50, font=("Arial", 12), bg="#D6D2C4", bd=2, relief="groove", highlightthickness=1, highlightbackground="#cccccc")
text_input.pack(pady=5)

tk.Label(root, text="Пароль:", bg="#f0f0f0", font=("Arial", 12)).pack(pady=10)
password_input = tk.Entry(root, show="*", width=30, font=("Arial", 12), bg="#ffffff", bd=2, relief="groove", highlightthickness=1, highlightbackground="#cccccc")
password_input.pack(pady=5)

encrypt_button = tk.Button(root, text="Зашифрувати", command=encrypt_message, width=20, height=2, bg="#4CAF50", fg="white", font=("Arial", 12))
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Розшифрувати", command=decrypt_message, width=20, height=2, bg="#f44336", fg="white", font=("Arial", 12))
decrypt_button.pack(pady=10)

tk.Label(root, text="Результат:", bg="#f0f0f0", font=("Arial", 12)).pack(pady=10)
text_output = tk.Text(root, height=10, width=50, font=("Arial", 12), bg="#D6D2C4", bd=2, relief="groove", highlightthickness=1, highlightbackground="#cccccc")
text_output.pack(pady=5)

root.mainloop()
