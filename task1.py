import hashlib
import os

def calculate_hash(file_path):
    """Calculates SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def save_hash(file_path, hash_value, hash_store='hashes.txt'):
    """Saves the file path and its hash to a storage file."""
    with open(hash_store, 'a') as f:
        f.write(f"{file_path}|{hash_value}\n")

def load_hashes(hash_store='hashes.txt'):
    """Loads all saved hashes from the file."""
    if not os.path.exists(hash_store):
        return {}
    hashes = {}
    with open(hash_store, 'r') as f:
        for line in f:
            path, hash_val = line.strip().split('|')
            hashes[path] = hash_val
    return hashes

def check_integrity(file_path, stored_hashes):
    """Compares the current file hash with stored hash."""
    current_hash = calculate_hash(file_path)
    stored_hash = stored_hashes.get(file_path)

    if stored_hash is None:
        print(f"[NEW] {file_path} - Not in stored records.")
    elif current_hash != stored_hash:
        print(f"[CHANGED] {file_path} - File has been modified!")
    else:
        print(f"[UNCHANGED] {file_path} - File is intact.")

def monitor_files(file_list):
    """Monitors a list of files for integrity."""
    stored_hashes = load_hashes()

    for file_path in file_list:
        if file_path not in stored_hashes:
            hash_value = calculate_hash(file_path)
            if hash_value:
                save_hash(file_path, hash_value)
                print(f"[ADDED] {file_path} - Hash stored.")
        else:
            check_integrity(file_path, stored_hashes)
if __name__ == "__main__":
    files_to_monitor = [
        'example1.txt',
        'example2.txt'
    ]
    monitor_files(files_to_monitor)
ans=input("Can we close this file?\n")
if ans=="yes":
    print("Ok bye")
elif ans=="no":
    print("Ok. Run again.")
else:
    print("Wrong option.Bye Bye!!")
