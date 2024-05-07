# \[Write-Up] Dreamhack - Double DES

대칭키 암호화 알고리즘 중 하나인 DES를 이용한 워게임 문제입니다. prob.py가 주어지고, exploit 코드를 만들어 flag를 얻을 수 있습니다.&#x20;



## DES&#x20;

1976년 미국 연방정보처리 표준 규격(FIPS)로 채택된 대칭키 암호 시스템입니다.&#x20;

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption><p>DES 암호화 과정</p></figcaption></figure>

DES는 64비트로 나눈 평문을 56비트의 키를 이용해서 64비트의 암호문을 만들어냅니다.&#x20;

1. 초기순열 (Initial Permutation, IP)&#x20;

미리 정해진 테이블을 이용해 64비트 입력을 비트 단위로 전치합니다.&#x20;

2. 암호화 과정&#x20;

* 확장 순열:&#x20;
* 라운드키와 XOR 연산:&#x20;
* S-박스:&#x20;
* P-박스:&#x20;
* 결과와&#x20;

3. 종료순열 (Final Permutation, FP)&#x20;

초기 순열의 역순으로 구성되어 있으며, 미리 정해진 테이블을 이용해 64비트 입력을 비트 단위로 전치합니다.&#x20;



## prob.py&#x20;

````python
```python
#!/usr/bin/env python3
from Crypto.Cipher import DES
import signal
import os

if __name__ == "__main__":
    signal.alarm(15)

    with open("flag", "rb") as f:
        flag = f.read()
    
    key = b'Dream_' + os.urandom(4) + b'Hacker'
    key1 = key[:8]
    key2 = key[8:]
    print("4-byte Brute-forcing is easy. But can you do it in 15 seconds?")
    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    encrypt = lambda x: cipher2.encrypt(cipher1.encrypt(x))
    decrypt = lambda x: cipher1.decrypt(cipher2.decrypt(x))

    print(f"Hint for you :> {encrypt(b'DreamHack_blocks').hex()}")

    msg = bytes.fromhex(input("Send your encrypted message(hex) > "))
    if decrypt(msg) == b'give_me_the_flag':
        print(flag)
    else:
        print("Nope!")
```
````



## exploit.py

````python
```python
from pwn import *
from Crypto.Cipher import DES

io = process(["python3", "prob.py"])
io = remote("host3.dreamhack.games", 20135)

io.recvuntil(b":> ")
hint = bytes.fromhex(io.recvline().decode())

conflict = dict()

for i in range(65536):
    b = i.to_bytes(2, "big")
    cipher = DES.new(b"Dream_" + b, DES.MODE_ECB)
    enc = cipher.encrypt(b"DreamHack_blocks")
    conflict[enc] = b"Dream_" + b

for i in range(65536):
    b = i.to_bytes(2, "big")
    cipher = DES.new(b + b"Hacker", DES.MODE_ECB)
    dec = cipher.decrypt(hint)

    if dec in conflict: 
        key1 = conflict[dec]
        key2 = b + b"Hacker"
        break

cipher1 = DES.new(key1, DES.MODE_ECB)
cipher2 = DES.new(key2, DES.MODE_ECB)
encrypt = lambda x: cipher2.encrypt(cipher1.encrypt(x))
assert encrypt(b"DreamHack_blocks") == hint

io.sendlineafter(b'> ', encrypt(b"give_me_the_flag").hex().encode())

flag = eval(io.recvline())
io.close()

print(flag.decode())

```
````
