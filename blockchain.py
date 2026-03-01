import hashlib

def calculate_hash(index, filename, file_hash, previous_hash):
    value = f"{index}{filename}{file_hash}{previous_hash}"
    return hashlib.sha256(value.encode()).hexdigest()