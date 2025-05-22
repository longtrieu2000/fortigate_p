from cryptography.fernet import Fernet
import os

# Load key
with open("secret.key", "rb") as f:
    key = f.read()

fernet = Fernet(key)

# Giải mã file .env.enc
with open(".env.enc", "rb") as f:
    encrypted = f.read()

decrypted = fernet.decrypt(encrypted).decode()

#with open(".env_dec", "w", encoding="utf-8") as f:
#    f.write(decrypted)

# Nạp vào biến môi trường
for line in decrypted.splitlines():
    if "=" in line:
        k, v = line.strip().split("=", 1)
        os.environ[k] = v

# Kiểm tra
#print("🔑 VAULT_TOKEN =", os.environ.get("VAULT_TOKEN"))