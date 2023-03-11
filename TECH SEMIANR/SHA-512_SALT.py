import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    password = password.encode()
    salted_password = salt + password
    hashed_password = hashlib.sha512(salted_password).hexdigest()
    return salt, hashed_password


password = "TECHNICALSEMINAR"
salt, hashed_password = hash_password(password)
print("Salt:", salt)
print("Hashed password:", hashed_password)