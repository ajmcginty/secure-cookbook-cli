import time
import os
from utils.storage import add_user, user_exists, wrong_password, get_user_key
from utils.encryption import encrypt_password

user_info = {}

def register():
    print("Registering new user...")

    while True:
        username = input("Enter a username: ").strip().lower()
        if user_exists(username):
            print("Error: Username already exists, please try again")
        else:
            break
    
    while True:
        password = input("Enter a password: ")
        password_confirm = input("Please confirm your password: ")

        if password != password_confirm:
            print("Error: passwords do not match")
        else:
            print("User registered!!!")
            break
    salt_b64, password_key, salt2_b64 = encrypt_password(password)
    user_info = {
        "salt": salt_b64,
        "key": password_key,
        "salt2": salt2_b64
    }
    add_user(username, user_info)

def login():
    print("Logging in...")
    while True:
        username = input("Please enter your username: ").strip().lower()
        if user_exists(username):
            break
        else:
            print("Error: username doesn't exist, please try again")

    while True:
        password = input("Please enter your password: ")
        if wrong_password(password, username):
            print("Error: Incorrect password")
        else:
            print("Login successful!!!")
            break

    k_user = get_user_key(username, password)
    return username, k_user
        
