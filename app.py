# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet   

# # Initialize session state for store_data and logged_in_user
# if "store_data" not in st.session_state:
#     st.session_state.store_data = {}

# if "logged_in_user" not in st.session_state:
#     st.session_state.logged_in_user = None


# # 1 generate a key for encryption and decryption
# # This key should be kept secret and secure
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)




# # 2 in memory store data
# store_data = st.session_state.store_data
# # Initialize the store_data dictionary

# failed_attempts = 0



# # 3 function to hash password
# def hash_passkey(passkey):  
#     return hashlib.sha256(passkey.encode()).hexdigest()

# #4 function to encrypt data
# def encrypt_data(data,passkey):
#     return cipher.encrypt(data.encode()).decode()

# # # 5 function to decrypt data
# # def decrypt_data( encrypt_data): 
# #     return  cipher.decrypt(encrypt_data).encode()

# # 6 function to check if the password is correct
# def check_password(stored_password, password):
#     return stored_password == hash_passkey(password) 

# def decrypt_data(encrypted_data, passkey):
#     global failed_attempts
#     hashed_passkey = hash_passkey(passkey)
    
#     # Check if the passkey is correct

#     for key, value in store_data.items():
#         if value["encrypted_text"] == encrypted_data and value["passkey"] == hashed_passkey:
#             failed_attempts = 0
#             return cipher.decrypt(encrypted_data.encode()).decode()

#     failed_attempts=+1
#     return None

# #7 streamlit UI
# st.title("Data Secure App 🔒 ")
    
#     #8 menu options
# menu=["Home", "Register", "Log in", "Encrypt Data", "Decrypt Data"]
# choice=st.sidebar.selectbox("Select an option", menu)
    
    
    
#     # for registration user
# if st.sidebar("Sign Up"):
#     st.header("Sign Up")
#     new_username=st.text_input("Username")
#     new_password=st.text_input("Password", type="password")
#     confirm_password=st.text_input("Confirm Password", type="password")
    
#     if st.button("Register"):
#         if new_username in store_data:
#             st.error("Username already exists. Please choose a different one.")
#         elif new_password != confirm_password:
#             st.error("Passwords do not match. Please try again.")
#         else:
#             hashed_passkey = hash_passkey(new_password)
#             store_data[new_username] = {
#                 "passkey": hashed_passkey,
#                 "encrypted_text": None
#             }
#             st.success("Registration successful! You can now log in.")
            
#             # 9 redirect to login page
            
#             if st.sidebar("Sign in"):
#                 st.header("Sign in")
#                 username = st.text_input("Username")
#                 password = st.text_input("Password", type="password")       
                
#                 if st.button("Sign in"):
#                     if username in store_data and check_password(store_data[username]["passkey"], password):
#                         st.success("Successfully logged in")
#                     else:
#                         st.error("Invalid username or password")
#                         failed_attempts += 1
#                         if failed_attempts >= 3:
#                             st.error("Too many failed attempts. Please try again later.")
#                             st.stop()   
#                         else:
#                             st.warning(f"Failed attempts: {failed_attempts}. Please try again.")
    
    
#     #  for  choosing homepage
# if choice =="Home":
#         st.subheader("Welcome to the Data Secure App!")
#         st.write("This app allows you to encrypt and decrypt data securely.")
#         st.write("Please log in to access the features.")

            
#             #  for  choosing encrypt data page 
# elif choice == "Encrypt Data":
#         st.header("Encrypt Data")
#         username=st.text_input("Username")
#         password=st.text_input("Password", type="password")
#         data=st.text_input("Enter your text to encrypt")
        
#         if st.button("Encrypt"): 
#             if username in store_data  and check_password(store_data[username]["passkey"], password): 
#                 encrypt_text=encrypt_data(data, password)
                
#                 store_data[username]={
#                     "encrypted_text": encrypt_text,
#                     "passkey": hash_passkey(password)
#                 }
                
#                 st.success("Data encrypted successfully!")
#                 st.write("Encrypted Data:", encrypt_text)
#             else: 
#                 st.error("Invalid username or password")
# #  failed_attempts += 1
# # # if failed_attempts >= 3:
# # #  st.error("Too many failed attempts. Please try again later.")
# # st.stop()   
# #else:
# # # st.warning(f"Failed attempts: {failed_attempts}. Please try again.")#

#         #  for  choosing decrypt data page
# elif choice =="Decrypt data":
#             st.header("Decrypt Data")
#             username=st.text_input("Username")
#             password=st.text_input("Password", type="password")
#             encrypted_data=st.text_input("Enter your encrypted text")
            
#             if st.button("Decrypt"): 
#                 if username and check_password(store_data[username]["passkey"], password): 
#                     decrypted_text=decrypt_data(encrypted_data, password)
                    
#                     if decrypted_text:
#                         st.success("Data decrypted successfully!")
#                         st.write("Decrypted Data:", decrypted_text)
#                     else:
#                         st.error("Invalid username or password")
#                         failed_attempts += 1
#                         if failed_attempts >= 3:
#                             st.error("Too many failed attempts. Please try again later.")
#                             st.stop()   
#                         else:
#                             st.warning(f"Failed attempts: {failed_attempts}. Please try again.")           
# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # --- Initialize session state ---
# if "store_data" not in st.session_state:
#     st.session_state.store_data = {}

# if "logged_in_user" not in st.session_state:
#     st.session_state.logged_in_user = None

# if "failed_attempts" not in st.session_state:
#     st.session_state.failed_attempts = 0

# # --- Generate encryption key and cipher ---
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # --- Hashing function ---
# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# # --- Encrypt data ---
# def encrypt_data(data):
#     return cipher.encrypt(data.encode()).decode()

# # --- Decrypt data ---
# def decrypt_data(encrypted_data):
#     return cipher.decrypt(encrypted_data.encode()).decode()

# # --- Password check ---
# def check_password(stored_password, entered_password):
#     return stored_password == hash_passkey(entered_password)

# # --- Streamlit UI ---
# st.title("🔐 Data Secure App")

# menu = ["Home", "Register", "Log in", "Encrypt Data", "Decrypt Data"]
# choice = st.sidebar.selectbox("Select an option", menu)

# store_data = st.session_state.store_data

# # --- Home Page ---
# if choice == "Home":
#     st.subheader("Welcome to the Data Secure App!")
#     st.write("Register or log in to encrypt/decrypt your data securely.")

# # --- Register Page ---
# elif choice == "Register":
#     st.subheader("Sign Up")
#     new_username = st.text_input("Username")
#     new_password = st.text_input("Password", type="password")
#     confirm_password = st.text_input("Confirm Password", type="password")

#     if st.button("Register"):
#         if new_username in store_data:
#             st.error("Username already exists. Choose a different one.")
#         elif new_password != confirm_password:
#             st.error("Passwords do not match.")
#         else:
#             store_data[new_username] = {
#                 "passkey": hash_passkey(new_password),
#                 "encrypted_text": None
#             }
#             st.success("Registration successful!")

# # --- Login Page ---
# elif choice == "Log in":
#     st.subheader("Log In")
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")

#     if st.button("Log In"):
#         if username in store_data and check_password(store_data[username]["passkey"], password):
#             st.session_state.logged_in_user = username
#             st.success(f"Welcome {username}!")
#             st.session_state.failed_attempts = 0
#         else:
#             st.error("Invalid credentials.")
#             st.session_state.failed_attempts += 1
#             if st.session_state.failed_attempts >= 3:
#                 st.error("Too many failed attempts. Please try again later.")
#                 st.stop()

# # --- Encrypt Data ---
# elif choice == "Encrypt Data":
#     st.subheader("Encrypt Data")
#     if st.session_state.logged_in_user:
#         data = st.text_input("Enter text to encrypt")

#         if st.button("Encrypt"):
#             encrypted = encrypt_data(data)
#             store_data[st.session_state.logged_in_user]["encrypted_text"] = encrypted
#             st.success("Data encrypted successfully!")
#             st.write("Encrypted Text:", encrypted)
#     else:
#         st.warning("Please log in first.")

# # --- Decrypt Data ---
# elif choice == "Decrypt Data":
#     st.subheader("Decrypt Data")
#     if st.session_state.logged_in_user:
#         encrypted_data = st.text_input("Enter encrypted text")

#         if st.button("Decrypt"):
#             try:
#                 stored_encrypted = store_data[st.session_state.logged_in_user]["encrypted_text"]
#                 if encrypted_data == stored_encrypted:
#                     decrypted = decrypt_data(encrypted_data)
#                     st.success("Data decrypted successfully!")
#                     st.write("Decrypted Text:", decrypted)
#                 else:
#                     st.error("Encrypted text does not match stored data.")
#             except Exception as e:
#                 st.error("Decryption failed. Make sure the encrypted text is correct.")
#     else:
#         st.warning("Please log in first.")



import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os

# --- Secret Key Management ---

KEY_FILE = "secret.key"

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)

# --- Session state init ---
if "store_data" not in st.session_state:
    st.session_state.store_data = {}

if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Utility functions ---

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data.encode()).decode()

def check_password(stored_password, entered_password):
    return stored_password == hash_passkey(entered_password)

# --- Streamlit UI ---
st.title("🔐 Data Secure App")

menu = ["Home", "Register", "Log in", "Encrypt Data", "Decrypt Data"]
choice = st.sidebar.selectbox("Select an option", menu)

store_data = st.session_state.store_data

# Home Page
if choice == "Home":
    st.subheader("Welcome to the Data Secure App!")
    st.write("Register or log in to encrypt/decrypt your data securely.")

# Register
elif choice == "Register":
    st.subheader("Sign Up")
    new_username = st.text_input("Username")
    new_password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if new_username in store_data:
            st.error("Username already exists. Choose a different one.")
        elif new_password != confirm_password:
            st.error("Passwords do not match.")
        else:
            store_data[new_username] = {
                "passkey": hash_passkey(new_password),
                "encrypted_text": None
            }
            st.success("Registration successful! You can now log in.")

# Log in
elif choice == "Log in":
    st.subheader("Log In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Log In"):
        if username in store_data and check_password(store_data[username]["passkey"], password):
            st.session_state.logged_in_user = username
            st.success(f"Welcome {username}!")
            st.session_state.failed_attempts = 0
        else:
            st.error("Invalid credentials.")
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.error("Too many failed attempts. Please try again later.")
                st.stop()

# Encrypt Data
elif choice == "Encrypt Data":
    st.subheader("Encrypt Data")
    if st.session_state.logged_in_user:
        data = st.text_input("Enter text to encrypt")
        if st.button("Encrypt"):
            encrypted = encrypt_data(data)
            store_data[st.session_state.logged_in_user]["encrypted_text"] = encrypted
            st.success("Data encrypted successfully!")
            st.write("Encrypted Text:", encrypted)
    else:
        st.warning("Please log in first.")

# Decrypt Data
elif choice == "Decrypt Data":
    st.subheader("Decrypt Data")
    if st.session_state.logged_in_user:
        encrypted_data = st.text_input("Enter encrypted text")
        if st.button("Decrypt"):
            try:
                stored_encrypted = store_data[st.session_state.logged_in_user]["encrypted_text"]
                if encrypted_data == stored_encrypted:
                    decrypted = decrypt_data(encrypted_data)
                    st.success("Data decrypted successfully!")
                    st.write("Decrypted Text:", decrypted)
                else:
                    st.error("Encrypted text does not match stored data.")
            except Exception:
                st.error("Decryption failed. Make sure the encrypted text is correct.")
    else:
        st.warning("Please log in first.")
