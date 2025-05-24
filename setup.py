import keyring
import requests
import os
from cryptography.fernet import Fernet

Key=b'HXfbXk16CZ1y8XcgcbW0GnT0k-HtA7ezxKqcb5fFc-I='
f = Fernet(Key)

url = "https://raw.githubusercontent.com/VeduStorm/data/refs/heads/main/serviceAccountKey.enc?token=GHSAT0AAAAAADDL6LTPJKQ2V3CSKPTKLYDK2BQHASQ"
url2 = "https://raw.githubusercontent.com/VeduStorm/data/refs/heads/main/requirements.txt?token=GHSAT0AAAAAADDL6LTPMOK6TTPKJVXZRRRM2BRS4QA"

response = requests.get(url)
response2 = requests.get(url2)

if response2.status_code == 200:
    content2 = response2.text
    with open("requirements.txt", "w") as file:
        file.write(content2)
else:
    print("Failed to fetch (requirements):", response2.status_code)

if response.status_code == 200:
    content = response.text
    content = bytes(content, 'utf-8')
else:
    print("Failed to fetch (Account Key):", response.status_code)

decrypted = f.decrypt(content)

keyring.set_password("shadow_crypt", "account_key", decrypted.decode('utf-8'))

os.system("pip install -r requirements.txt")
os.remove("requirements.txt")
