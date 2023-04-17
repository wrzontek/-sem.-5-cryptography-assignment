from pwnlib.tubes.remote import remote

from utils import rsa_encrypt

# w kodzie źródłowym widzimy, że by zdobyć flag musimy zalogować się na użytkownika 'flag'
# tokenem użytkownika jest zaszyfrowany RSA username, a ponieważ w RSA do zaszyfrowania wystarczy klucz publiczny, który
# serwer nam podaje, możemy na swoim komputerze zaszyfrować nim 'flag' i zalogować się na otrzymany token

conn = remote('cryptotask.var.tailcall.net', 30000)
conn.recvuntil(b'7) Get encrypted flag')
conn.recvline()
conn.send(b'6\n')
RSA_PUB_KEY = str(conn.recvuntil(b'7) Get encrypted flag'))

RSA_PUB_KEY = RSA_PUB_KEY[RSA_PUB_KEY.find("-----BEGIN PUBLIC KEY-----"):
                          RSA_PUB_KEY.find("END PUBLIC KEY-----") + len("END PUBLIC KEY-----")]

RSA_PUB_KEY = RSA_PUB_KEY.replace(r'\n', '\n')



username = "flag"
token_int = int.from_bytes(username.encode(), byteorder='big')
token = int(rsa_encrypt(RSA_PUB_KEY, token_int))
print(token)

# logujemy się tym tokenem

conn.recvline()
conn.send(b'5\n')
conn.send(bytes(str(token), 'utf-8'))
conn.send(bytes('\n', 'utf-8'))
conn.recvline()

print(conn.recvline())  # Your bio is: flag{6ae29f75814549cc9094b8c11dbe22ee}\n
