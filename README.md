# Super Secret Recipe Cookbook

A command-line recipe manager implementing cryptographic security for a UC3M cryptography final project.

**Status:** Phases 1-3 complete (authentication), Phase 4 in progress (recipe encryption)

## Overview

This Python application demonstrates practical cryptography concepts:
- Secure password storage using Scrypt (never store passwords directly)
- User-specific encryption key derivation using PBKDF2
- Authenticated encryption with ChaCha20Poly1305 (in progress)

Users can register accounts, login securely, and store recipes. Each user has isolated recipe storage with their own encryption key derived from their password.

## Implementation Phases

### Phase 1: Basic Application - Complete
Basic user registration, login, and recipe storage.

### Phase 2: Secure Password Storage (Scrypt) - Complete
- Random salt (salt_1) generated per user with `os.urandom(16)`
- Scrypt hashing with N=2^14, r=8, p=1, 256-bit output
- Password hash and salt stored in Base64
- Login verification using `kdf.verify()`

### Phase 3: Key Derivation (PBKDF2) - Complete
- Second random salt (salt_2) generated per user
- PBKDF2-HMAC-SHA256 with 600,000 iterations
- 256-bit encryption key (k_user) derived at login
- Key kept in memory only, never stored

### Phase 4: Recipe Encryption (ChaCha20Poly1305) - In Progress
Need to implement:
- Complete `encrypt_recipe()` function (serialize data, generate nonce, encrypt)
- Create `decrypt_recipe()` function (decrypt, handle InvalidTag, deserialize)
- Modify `add_recipe()` to encrypt before storing
- Modify `view_recipe()` to decrypt when loading
- Pass k_user from main_menu to storage functions

## Installation

Requires Python 3.8+

```bash
# Create virtual environment (optional)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

## Usage

**Register:** Option 1, enter unique username and password (stored as Scrypt hash)

**Login:** Option 2, enter credentials (generates k_user for encryption)

**Add Recipe:** After login, option 1, enter name and instructions, type DONE when finished

**View Recipe:** After login, option 2, enter recipe name

## Project Structure

```
crypto-final-app/
├── main.py                 # Entry point
├── requirements.txt        # cryptography library
├── recipes.json           # Data storage (created on first run)
├── cli/
│   ├── login_menu.py      # Registration and login
│   └── main_menu.py       # Recipe management
└── utils/
    ├── encryption.py      # Crypto functions (Scrypt, PBKDF2, ChaCha20)
    └── storage.py         # JSON operations
```

## Data Storage

Current format (Phase 3):
```json
{
  "users": {
    "username": {
      "salt": "base64_salt_1",
      "key": "base64_scrypt_hash",
      "salt2": "base64_salt_2",
      "recipes": {
        "recipe_name": {
          "name": "recipe_name",
          "information": "plaintext_recipe"
        }
      }
    }
  }
}
```

After Phase 4:
```json
"recipes": {
  "recipe_name": {
    "name": "recipe_name",
    "nonce": "base64_nonce",
    "ciphertext": "base64_encrypted_data"
  }
}
```

## Cryptographic Details

**Registration:**
1. Generate salt_1 (16 bytes)
2. Scrypt(password, salt_1) → password hash
3. Generate salt_2 (16 bytes)
4. Store username, salt_1, hash, salt_2 (all Base64)

**Login:**
1. Load salt_1 and stored hash
2. Verify password with Scrypt
3. If correct, derive k_user = PBKDF2(password, salt_2, 600k iterations)
4. Keep k_user in memory for session

**Recipe Encryption (planned):**
1. Serialize recipe as JSON bytes
2. Generate 12-byte nonce
3. Encrypt with ChaCha20Poly1305(k_user)
4. Store ciphertext + nonce (Base64)

**Recipe Decryption (planned):**
1. Load ciphertext and nonce
2. Decrypt with ChaCha20Poly1305(k_user)
3. Handle InvalidTag if data tampered
4. Deserialize JSON

## Current Limitations

- Recipes not encrypted yet (Phase 4 incomplete)
- k_user generated but not used
- Recipe names visible in JSON
- No input validation
- No edit/delete functionality
- JSON storage (not production-ready)

## Testing

1. Register user
2. Try wrong password (should fail)
3. Login with correct password
4. Add recipes
5. View recipes
6. Create second user (verify isolation)
7. Check recipes.json (passwords hashed, recipes currently plaintext)

## Requirements

```
cryptography>=46.0.0
```

---

Cryptography Final Project - UC3M
