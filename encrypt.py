from cryptography.fernet import Fernet
# Tạo key (chạy 1 lần)
key = Fernet.generate_key()
with open("secret.key", "wb") as f:
    f.write(key)

# Mã hóa file .env
with open(".env", "rb") as f:
    data = f.read()

fernet = Fernet(key)
encrypted = fernet.encrypt(data)

with open(".env.enc", "wb") as f:
    f.write(encrypted)

print("✅ Đã mã hóa thành công -> .env.enc")