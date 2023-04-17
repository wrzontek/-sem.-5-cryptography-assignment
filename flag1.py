from utils import aes_encrypt_nonce, aes_decrypt
from pwn import *

conn = remote('cryptotask.var.tailcall.net', 30000)
# conn = remote('localhost', 13371)
conn.recvuntil(b'7) Get encrypted flag')
conn.recvline()
conn.send(b'1\n')
encrypted_flag = str(conn.recvuntil(b'7) Get encrypted flag')[8: 132])
conn.recvline()
print("encrypted flag: ", encrypted_flag)

# wykorzystujemy podatność na dowolną zmianę dowolnej liczby pierwszych bajtów klucza, wynikająco z źle zastosowanego xor/enumerate
# możemy zaszyfrować tekst, wyzerować pierwszy bajt, zaszyfrować tekst, wyzerować drugi bajt i tak dalej,
# co daje nam wystarczająco informacji do szybkiego brute forca
# klucz ma 16 bajtów, chcemy go brute forceować po jednym bajcie
# (tylko 256 możliwości a AES liczy się szybko, także to żaden problem)
# z uwagi na nonce musimy od razu tablicować wszystkie wyniki

encryption_results = ["" for i in range(16)]

for i in range(16):
    conn.send(b'3\n')
    conn.send(b'0123456789abcdef\n')  # dowolny poprawny hex tak naprawdę
    encryption = str(conn.recvuntil(b'7) Get encrypted flag'))
    encryption_start_index = encryption.find("Message to encrypt: ") + len("Message to encrypt: ")
    encryption = encryption[encryption_start_index: encryption_start_index + 82]
    encryption_results[i] = encryption
    print(i, encryption)

    conn.send(b'2\n')
    new_key = b'30313233343536373839616263646566'[0: 2 * (i + 1)] # secret.hex() żeby xorowało się do zer
    # print(new_key)
    conn.send(new_key)
    conn.send(bytes('\n', 'utf-8'))
    conn.recvuntil(b'7) Get encrypted flag')

# encryption_results[15] ma '0123456789abcdef' (nasz dowolny hex)
# zaszyfrowane kluczem z wyzerowanymi wszystkimi bajtami poza ostatnim

# encryption_results[15 - i] ma '0123456789abcdef' (nasz dowolny hex)
# zaszyfrowane kluczem z wyzerowanymi wszystkimi bajtami poza i+1 ostatnimi

# będziemy idąć od tyłu brute forcować po jednym bajcie klucza odtwarzając go w całośći

all_possible_bytes = bytes([i for i in range(256)])
aes_key = bytes([0 for i in range(16)])

for i in range(16):
    result = encryption_results[15 - i]
    nonce = bytes.fromhex(result.split(":")[0])

    for byte in all_possible_bytes:
        aes_key = bytearray(aes_key)
        aes_key[15 - i] = byte
        aes_key = bytes(aes_key)

        encrypted = aes_encrypt_nonce(aes_key, bytes.fromhex('0123456789abcdef'), nonce)
        if encryption_results[15 - i] == encrypted:
            break

# print("key: ", aes_key)
# otrzymanym kluczem odszyfrowujemy flagę

encrypted_flag = str(encrypted_flag)
print(aes_decrypt(aes_key,
                  bytes.fromhex(encrypted_flag.split(":")[1]),
                  bytes.fromhex(encrypted_flag.split(":")[0][2:])))






