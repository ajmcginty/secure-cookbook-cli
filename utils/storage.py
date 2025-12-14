import json
import os
from utils.encryption import (
    verify_password, generate_user_key, encrypt_recipe, decrypt_recipe,
    load_private_key, load_public_key, load_certificate,
    sign_data, verify_signature, verify_certificate
)

FILENAME = "recipes.json"

def load_data():
    """
    Load data from JSON file or initialize if missing.
    """
    if os.path.exists(FILENAME):
        with open(FILENAME, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {"users": {}}
    return {"users": {}}

def save_data(data):
    """
    Write the JSON data back to the file.
    """
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=4)

def user_exists(username):
    """
    Check if a username is already in storage.
    """
    data = load_data()
    return username in data.get("users", {})

def add_user(username, user_info):
    """
    Add a new user to the JSON file.
    """
    data = load_data()
    data["users"][username] = user_info
    save_data(data)

def wrong_password(entered_password, username):
    """
    Check if password entered at login matches stored password
    """
    data = load_data()
    user = load_data().get("users", {}).get(username)

    salt_b64 = user.get("salt")
    key_b64 = user.get("key")
    
    is_correct = verify_password(entered_password, salt_b64, key_b64)
    
    return not is_correct

def add_recipe(username, recipe_name, recipe_entry, user_key, password):
    """
    Adds recipe input to JSON (encrypted and signed).
    """
    data = load_data()
    user = data["users"].get(username)

    if "recipes" not in user:
        user["recipes"] = {}

    # Encrypt the recipe
    nonce_b64, ciphertext_b64 = encrypt_recipe(recipe_entry, user_key)
    
    # Sign the recipe data
    private_key = load_private_key(username, password)
    signature_b64 = sign_data(recipe_entry, private_key)
    
    # Store encrypted recipe with signature
    user["recipes"][recipe_name] = {
        "nonce": nonce_b64,
        "ciphertext": ciphertext_b64,
        "signature": signature_b64
    }
    
    save_data(data)

def view_recipe(username, recipe_name, user_key):
    """
    View a specific recipe for a given user (decrypted and verified).
    """
    data = load_data()
    user = data["users"].get(username)

    if user is None:
        raise ValueError(f"User '{username}' not found.")

    recipes = user.get("recipes", {})
    encrypted_recipe = recipes.get(recipe_name)

    if encrypted_recipe is None:
        print(f"Recipe '{recipe_name}' not found for user '{username}'.")
        return None
    
    # Verify certificate first
    cert = load_certificate(username)
    cert_valid = verify_certificate(cert)
    
    # Decrypt the recipe
    nonce_b64 = encrypted_recipe["nonce"]
    ciphertext_b64 = encrypted_recipe["ciphertext"]
    recipe = decrypt_recipe(nonce_b64, ciphertext_b64, user_key)
    
    # Verify signature
    signature_b64 = encrypted_recipe["signature"]
    public_key = load_public_key(username)
    signature_valid = verify_signature(recipe, signature_b64, public_key)
    
    # Display recipe with verification status
    print(f"\nRecipe: {recipe_name}\n{'-' * (9 + len(recipe_name))}")
    print(f"Name: {recipe['name']}")
    print(f"Information:\n{recipe['information']}")
    print(f"\n--- Security Status ---")
    print(f"Certificate Valid: {'✓ YES' if cert_valid else '✗ NO'}")
    print(f"Signature Valid: {'✓ YES' if signature_valid else '✗ NO'}")
    print()
    return recipe

def get_user_key(username, password):
    """
    Loads username and salt to generate a user key, then returns user key
    """

    data = load_data()
    user = data["users"][username]
    salt_2_b64 = user["salt2"]
    user_key = generate_user_key(password, salt_2_b64)
    return user_key


    
