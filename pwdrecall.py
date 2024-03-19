#!/usr/bin/env python

import simple_term_menu as stm
import time
import json

import base64
import getpass
from passlib.hash import argon2
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

DATAFILE = 'pwdrecall.vault'

class AESCipher(object):
    def __init__(self, key):
        kdf = PBKDF2(key, "PWDRecall key salt", 64, 1000)
        self.bs = AES.block_size
        self.key = kdf[:32]

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def load_decrypt_vault(file = DATAFILE):
    global CIPHER

    try:
        with open(file, 'r') as f:
            text = f.read()
        set_master_pwd(new_password=False)
    except:
        print("Cannot open the vault. Creating a new one...")
        set_master_pwd(new_password=True)
        return []
    
    try:
        text_decoded = CIPHER.decrypt(text)
    except:
        text_decoded = ''

    try:
        return sorted(json.loads(text_decoded), key = lambda x: x['name'])
    except:
        if not text_decoded:
            print("Error decrypting the vault...")
        else:
            print("Error converting decrypted text into json...")
        response = input("Do you want to create a new vault? All data from the existing vault will be lost after save. (y/n): ")
        if response.lower() in ('y', 'yes'):
            set_master_pwd(new_password=True)
            return []
        else:
            print("Exiting...")
            exit()
    
def encrypt_save_vault(file = DATAFILE):
    global CIPHER, ENTRIES

    text = json.dumps(ENTRIES)
    encrypted_text = CIPHER.encrypt(text)
    with open(file, 'w') as f:
        f.write(encrypted_text.decode('utf-8'))

def estimate_argon2_rounds(target_time = 0.5, initial_rounds = 1, n_tries = 4):
    rounds = initial_rounds
    for i in range(n_tries):
        t0 = time.time()
        argon2.using(rounds=rounds).hash('Secret for test purposes')
        dt = time.time()-t0
        rounds = max(round(rounds * target_time / dt), 1)
    return rounds

def get_new_entry():
    print('***** New Entry **************')
    name = input("Entry name > ")
    if name == '':
        return None
    pwd = getpass.getpass("Secret > ")    
    pwd_confirmation = getpass.getpass("Confirm secret > ")
    if pwd == pwd_confirmation:
        pwd_hash = argon2.using(rounds=ARGON2_ROUNDS).hash(pwd)
        return {'name': name, 'hash': pwd_hash}
    else:
        print("The entered secrets are different!")
        return None

def check_entry(entry):
    print('***** Verify Secret ********')
    print(f"Entry: {entry['name']}")
    pwd = getpass.getpass("Verify secret > ")
    check = argon2.verify(pwd, entry['hash'])
    return check

def delete_entries():
    global ENTRIES, menu_options
    stm_menu = stm.TerminalMenu(
            [entry['name'] for entry in ENTRIES],
            multi_select = True,
            show_multi_select_hint = True
        )
    indices = stm_menu.show()
    if indices:
        print("Deleting selected entries...")
        ENTRIES = [ENTRIES[i] for i in range(len(ENTRIES)) if i not in indices]
        menu_options = [menu_options[i] for i in range(len(menu_options)) if i-5 not in indices]

def set_master_pwd(new_password = False):
    global CIPHER
    pwd = getpass.getpass("Enter master password > ")
    pwd_confirmation = None

    if new_password:
        while not pwd or pwd != pwd_confirmation:
            if not pwd:
                if pwd=='':
                    print("Empty password. Please try again...")
                pwd = getpass.getpass("Enter master password > ")
                continue
            else:
                pwd_confirmation = getpass.getpass("Verify master password > ")
                if not pwd_confirmation or pwd_confirmation != pwd:
                    print("Passwords don't match. Try again...")
                    pwd = None
                    continue

    CIPHER = AESCipher(pwd)    

if __name__ == "__main__":
    ENTRIES = load_decrypt_vault()
    ARGON2_ROUNDS = estimate_argon2_rounds()

    menu_options = ['> Add new entry', '> Save database', '> Exit', '> Delete entries', '> Change master password'] +\
        ['(.) ' + entry['name'] for entry in ENTRIES]
    while 1 == 1:
        tm = stm.TerminalMenu(
            menu_options,
            multi_select = False,
            cursor_index = 5
        )
        idx = tm.show()

        if idx == 0:
            entry = get_new_entry()
            if entry:
                ENTRIES.append(entry)
                menu_options.append('(=) ' + entry['name'])
        elif idx == 1:
            encrypt_save_vault()
        elif idx == 2:
            exit()
        elif idx == 3:
            delete_entries()
        elif idx == 4:
            set_master_pwd(new_password = True)
        else:
            entry = ENTRIES[idx-5]
            check = check_entry(entry)
            if not check:
                print('Sorry, that is incorrect.')
            else:
                print('Good job!')
                menu_options[idx] = '(+)' + menu_options[idx][3:]