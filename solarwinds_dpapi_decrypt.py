import struct
from Crypto.Cipher import AES
import sys


def decrypt_dpapi_blob(blob, masterkey):
    if blob[:16] != b"\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb":
        raise ValueError("Not a valid DPAPI blob")

    encrypted_data = blob[36:]  # Skip 36-byte header

    # Truncate to AES block size if necessary
    if len(encrypted_data) % 16 != 0:
        encrypted_data = encrypted_data[: len(encrypted_data) - (len(encrypted_data) % 16)]

    iv = b"\x00" * 16
    cipher = AES.new(masterkey, AES.MODE_CBC, iv)
    return cipher.decrypt(encrypted_data)


def main():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python dpapi_decrypt.py <default.dat> <masterkey (64 hex chars)> [output_file]")
        print("Example masterkey: ac2bce13b12389224044444a9b33339c3aaa3132575a408733390ec51112383627")
        print("\nTo extract this, grab the 'full:' field from the 'DPAPI_SYSTEM' secret in your Mimikatz dump.")
        return

    path = sys.argv[1]
    masterkey_input = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) == 4 else "default.dat.dec"

    if len(masterkey_input) < 64:
        print("[-] Error: Masterkey must be at least 64 hex characters (32 bytes).")
        return
    elif len(masterkey_input) > 64:
        print("[*] Warning: Masterkey is longer than 64 hex characters, using only the first 64.")
        masterkey_input = masterkey_input[:64]

    try:
        masterkey = bytes.fromhex(masterkey_input)
    except ValueError:
        print("[-] Error: Masterkey is not valid hexadecimal.")
        return

    with open(path, "rb") as f:
        data = f.read()

    sig = b"\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb"
    offset = data.find(sig)
    if offset == -1:
        print("[-] DPAPI signature not found in the file.")
        return

    blob = data[offset : offset + 174]
    print(f"[+] Found DPAPI blob at offset {offset}, size 174 bytes")

    try:
        decrypted = decrypt_dpapi_blob(blob, masterkey)
        print(f"[+] Decryption succeeded. Writing binary output to {output_file}")
        with open(output_file, "wb") as out_f:
            out_f.write(decrypted)
    except Exception as e:
        print(f"[-] Decryption failed: {str(e)}")


if __name__ == "__main__":
    main()
