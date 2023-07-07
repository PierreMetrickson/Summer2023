from pwn import *
from Crypto.Util.number import long_to_bytes

def xor(s1, s2):
    return ''.join([str(int(a) ^ int(b)) for a,b in zip(s1,s2)])

r = remote("chalp.hkcert21.pwnable.hk", 28102)
r.recvuntil(b'> ')
r.sendline(b'cfb data '+ b'0'*160)
s1 = r.recvline()[:-1]
r.recvuntil(b'> ')
r.sendline(b'ofb flag')
s2 = r.recvline()[:-1]
r.close()
t = xor(bin(int(s1,16))[2:],bin(int(s2,16))[2:])
print(long_to_bytes(int(t,2)))
