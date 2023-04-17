#!/usr/bin/env python3
from utils import read_until, xor, aes_encrypt, rsa_decrypt, rsa_encrypt, convert_to_public
from pathlib import Path
from os import urandom
from socketserver import TCPServer, ThreadingMixIn, BaseRequestHandler
import string


FLAG1 = Path('flag_1.txt').read_text().strip()
FLAG2 = Path('flag_2.txt').read_text().strip()
FLAG3 = Path('flag_3.txt').read_text().strip()

RSA_PRIV_KEY = Path('server.pem').read_text()


class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


class TCPHandler(BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        self.aes_key = bytearray(urandom(16))
        self.enc_flag1 = aes_encrypt(self.aes_key, FLAG1.encode())
        self.users = {'flag': FLAG2}
        print(f'AES key set to {self.aes_key.hex()}')
        super().__init__(*args, **kwargs)


    def send(self, text):
        self.sock.sendall(text.encode())


    def read_line(self):
        return read_until(self.sock, b'\n').decode().strip()


    def handle(self):
        self.sock = self.request
        print(f'{self.client_address} connected!')
        self.send('Welcome to the crypto task game!\n')
        try:
            while True:
                self.menu()
        except (EOFError, ConnectionResetError):
            pass


    def finish(self):
        print(f'{self.client_address} disconnected!')


    # -------- FLAG1 --------
    def cmd1_get_enc_flag(self):
        self.send(self.enc_flag1 + '\n')


    def cmd2_rekey(self):
        try:
            self.send('New key (hex): ')
            new_key_hex = self.read_line()
            new_key = bytes.fromhex(new_key_hex)
        except Exception:
            self.send('invalid key\n')
            return

        # xor the provided key with a secret for more security
        secret = b'0123456789abcdef'
        super_secret_key = xor(new_key, secret)

        for index, byte in enumerate(super_secret_key):
            self.aes_key[index] = byte

        self.send('Done!\n')


    def cmd3_encrypt(self):
        self.send('Message to encrypt: ')
        msg = self.read_line()
        encrypted = aes_encrypt(self.aes_key, bytes.fromhex(msg))
        self.send(encrypted + '\n')

    
    # -------- FLAG2 --------
    def cmd4_register(self):
        self.send('Your username: ')
        username = self.read_line()

        if username in self.users:
            self.send('This user is already registered\n')
        else:
            self.users[username] = 'Hi! I\'m a new user.'
            token_int = int.from_bytes(username.encode(), byteorder='big')
            rsa_token = rsa_encrypt(RSA_PRIV_KEY, token_int)
            self.send(f'Your token is {rsa_token}\n')


    def cmd5_login(self):
        self.send('Your token: ')
        token_int = int(self.read_line())
        token = int(rsa_decrypt(RSA_PRIV_KEY, token_int))
        token_bytes = (token.bit_length()+7) // 8
        username = int.to_bytes(int(token), token_bytes, byteorder='big').decode()

        if username not in self.users:
            self.send('This user is not registered\n')
        else:
            self.send(f'Hello {username}!\n')
            self.send(f'Your bio is: {self.users[username]}\n')


    def cmd6_get_pubkey(self):
        self.send(convert_to_public(RSA_PRIV_KEY) + '\n')


    # -------- FLAG3 --------
    def cmd7_otp(self):
        CHARSET = string.ascii_letters + string.digits + '{}_'
        ct = ''
        for char in FLAG3:
            assert char in CHARSET
            key = urandom(1)[0] % len(CHARSET)
            ct += CHARSET[(CHARSET.index(char) + key) % len(CHARSET)]
        self.send(f'Encrypted FLAG3: {ct}\n')


    def menu(self):
        self.send('''
Select an option:
--- symmetric crypto section
 1) Get encrypted flag
 2) Change the secret key
 3) Encrypt something
--- asymmetric crypto section
 4) Register
 5) Login
 6) Get server public key
--- one-time-pad - proven secure!
 7) Get encrypted flag
''')
        self.send('Choice: ')
        choice = self.read_line()
        
        if choice == '1':
            self.cmd1_get_enc_flag()
        elif choice == '2':
            self.cmd2_rekey()
        elif choice == '3':
            self.cmd3_encrypt()
        elif choice == '4':
            self.cmd4_register()
        elif choice == '5':
            self.cmd5_login()
        elif choice == '6':
            self.cmd6_get_pubkey()
        elif choice == '7':
            self.cmd7_otp()
        else:
            self.send('???\n')


def main():
    PORT = 13371
    try:
        with ThreadedTCPServer(('0.0.0.0', PORT), TCPHandler) as server:
            print(f'Server started on port {PORT}')
            server.serve_forever()
    except KeyboardInterrupt: # Ctrl-C
        print('Exiting...')

if __name__ == '__main__':
    main()
