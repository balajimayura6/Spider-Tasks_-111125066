import argparse
import hashlib
import string
import sys
#1-Caeser Lock
def caesar_encrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


#2-Hash Guard

def compute_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_file(filename, shift):
    with open(filename, 'r') as f:
        plaintext = f.read()
    ciphertext = caesar_encrypt(plaintext, shift)
    file_hash = compute_hash(plaintext)
    with open(filename + ".enc", 'w') as f:
        f.write(file_hash + "\n" + ciphertext)
    print(f"File encrypted → {filename}.enc")

def decrypt_file(filename, shift):
    with open(filename, 'r') as f:
        lines = f.readlines()
    stored_hash = lines[0].strip()
    ciphertext = ''.join(lines[1:])
    plaintext = caesar_decrypt(ciphertext, shift)
    recomputed_hash = compute_hash(plaintext)

    if stored_hash == recomputed_hash:
        print("Integrity check passed.")
    else:
        print("Tamper warning- file has been modified")
    print("\nDecrypted text:\n")
    print(plaintext)


#frequency analysis

def frequency_analysis(ciphertext):
    candidates = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = sum(decrypted.count(c) for c in "ETAOIN SHRDLU")  # crude scoring
        candidates.append((score, shift, decrypted))
    candidates.sort(reverse=True)
    print("\nTop 3 likely plaintexts:")
    for score, shift, text in candidates[:3]:
        print(f"Shift {shift}: {text}")


# CLI Setup

def main():
    parser = argparse.ArgumentParser(description="CryptoVault - Caesar + Hash Guard")
    parser.add_argument("action", choices=["encrypt", "decrypt", "crack"])
    parser.add_argument("filename")
    parser.add_argument("--shift", type=int, default=3)
    args = parser.parse_args()

    if args.action == "encrypt":
        encrypt_file(args.filename, args.shift)
    elif args.action == "decrypt":
        decrypt_file(args.filename, args.shift)
    elif args.action == "crack":
        with open(args.filename, 'r') as f:
            ciphertext = f.read()
        frequency_analysis(ciphertext)

if __name__ == "__main__":
    main()
