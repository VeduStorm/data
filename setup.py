import keyring
import requests
import os
from cryptography.fernet import Fernet

Key=b'HXfbXk16CZ1y8XcgcbW0GnT0k-HtA7ezxKqcb5fFc-I='
f = Fernet(Key)

url = "https://raw.githubusercontent.com/VeduStorm/data/refs/heads/main/serviceAccountKey.enc?token=GHSAT0AAAAAADDL6LTPJKQ2V3CSKPTKLYDK2BQHASQ"


response = requests.get(url)

if response.status_code == 200:
    content = response.text
    content = bytes(content, 'utf-8')
else:
    print("Failed to fetch:", response.status_code)

decrypted = f.decrypt(content)

keyring.set_password("shadow_crypt", "account_key", decrypted.decode('utf-8'))

os.system("pip install -r requirements.txt")
os.remove("requirements.txt")
