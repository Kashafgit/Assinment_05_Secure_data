import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# --- Constants ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
MASTER_PASSWORD = "admin123"

# --- Load or Generate Encryption Key ---
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

KEY = load_key()
cipher = Fernet(KEY)

# --- Data Handling ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# --- Session States ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False
if "login_required" not in st.session_state:
    st.session_state.login_required = False

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    for user, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# --- Sidebar Navigation ---
menu = ["🏠 Home", "🔐 Store Data", "🔍 Retrieve Data"]
if st.session_state.login_required:
    menu = ["🔐 Login Required"]

choice = st.sidebar.selectbox("📋 Navigation", menu)

# --- Home Page ---
if choice == "🏠 Home":
    st.title("🔐 Secure Data Encryption System")
    st.subheader("🛡️ Your Personal Digital Vault")
    st.write("Welcome! This app helps you **encrypt** and **securely store** your sensitive data.")
    st.markdown("### ✨ Features")
    st.markdown("""
    - 🔏 Secure data using strong encryption  
    - 🔍 Retrieve with password-protected access  
    - 🧠 Prevent brute-force with attempt limits  
    - 🔐 Reauthorization for extra security  
    """)
   

# --- Store Data ---
elif choice == "🔐 Store Data":
    st.header("📂 Store Your Secure Data")
    username = st.text_input("👤 Username")
    user_data = st.text_area("📝 Data to Secure")
    passkey = st.text_input("🔑 Passkey", type="password")

    if st.button("🔒 Encrypt & Save"):
        if username and user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[username] = {"encrypted_text": encrypted, "passkey": hashed}
            save_data(stored_data)
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill all fields before saving.")

# --- Retrieve Data ---
elif choice == "🔍 Retrieve Data":
    if st.session_state.reauthorized:
        st.success("✅ Reauthorized successfully!")

    st.header("🔓 Retrieve Encrypted Data")
    username = st.text_input("👤 Username")
    passkey = st.text_input("🔑 Passkey", type="password")

    if st.button("🧩 Decrypt"):
        if username and passkey:
            if username not in stored_data:
                st.error("❌ Username not found!")
            else:
                encrypted_text = stored_data[username]["encrypted_text"]
                result = decrypt_data(encrypted_text, passkey)
                if result:
                    st.success("✅ Decrypted successfully!")
                    st.text_area("🔍 Your Data:", result, height=150)
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔐 Too many failed attempts! Reauthorization required.")
                        st.session_state.login_required = True
                        st.rerun()
        else:
            st.warning("⚠️ Please fill in both fields.")

# --- Login Page ---
elif choice == "🔐 Login Required":
    st.header("🔐 Reauthorization Required")
    login_input = st.text_input("🔑 Enter Master Password", type="password")

    if st.button("🚪 Login"):
        if login_input == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.session_state.login_required = False
            st.success("✅ Logged in successfully!")
            st.rerun()
        else:
            st.error("❌ Incorrect master password.")
