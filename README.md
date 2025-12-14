# Super Secret Recipe Cookbook

A command-line recipe manager implementing cryptographic security for a UC3M cryptography final project.


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


## Requirements

```
cryptography>=46.0.0
```

---

Cryptography Final Project - UC3M
