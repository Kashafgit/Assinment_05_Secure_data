# 🔐 Secure Data Encryption App

A simple Streamlit app to **encrypt and store** sensitive data securely using custom passkeys. Decrypt it later using the same credentials!

## ⚙️ Features

- 🔏 Encrypt & store any data
- 🔐 Decrypt using your passkey
- 🚫 3 failed attempts = lockout
- 🧠 Re-login with master password (`admin123`)
- 📁 Local data storage (JSON)
- 🔑 AES encryption with `Fernet`

## 🚀 Getting Started

```bash
git clone https://github.com/Kashafgit/Assinment_05_Secure_data.git
cd secure-data-encryption
pip install streamlit cryptography
streamlit run app.py

📂 Files
app.py – Main app

data.json – Encrypted data

secret.key – Encryption key

👩‍💻 Made by Kashaf
💖 Focused on security, design & user experience


For demo purposes only. Not for storing highly sensitive data.