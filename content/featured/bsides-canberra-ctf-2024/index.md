+++ 
weight = 4
tags = ["ctf", "crypto", "cryptography", "writeup", "onsite", "bsides"] 
categories = ["CTF Writeups", "writeups" , "crypto", "onsite"] 
publishDate = 1727510000
description = "Writeups for crypto(graphy) challenges from BSides Canberra CTF 2024!" 
title_img = """{{< image src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTU3wnWUBGZpKQpVQNHk11hVTzAa-0mrs7sbQ&s" alt="" style="border-radius: 5px; height: auto; width: 3em; display: inline; vertical-align: middle; " >}}"""
title = """Crypto Writeups - BSides Canberra CTF 2024"""
cover = "big_cardboard_again.jpg"
katex = "true"
+++

# Overview

Last week I went to BSides Canberra 2024 to see the amazing talks, meet people, and of course, play CTF. After 2 days of solving interesting challenges, my team [Emu Exploit](https://x.com/EmuExploit) managed to get 2nd place overall!

{{< image src="./img/scoreboard.png" alt="" position="center" style="border-radius: 5px; width: 100%" >}}

I was basically the only person in the team who was willing to do crypto :< so I decided to write up the crypto challenges I solved. Enjoy!

# Challenges Overview

| **Challenge**                                              | **Category** | **Solves** |
| ---------------------------------------------------------- | ------------ | ---------- |
| [Discrete Add-a-rithm](#discrete-add-a-rithm---43-solves) | crypto       | 43         |
| [Psionic](#psionic---10-solves)                            | crypto       | 10         |
| [Public Service](#public-service---8-solves)               | crypto       | 8          |
| [arpeeceethree](#arpeeceethree---3-solves)                 | crypto       | 3          |

# Discrete Add-a-rithm - 43 solves

> You enter a room. On the wall is a large tapestry showing two people exchanging gifts. What could it mean?

We are provided with two files, `discreteAddarithm.py` and `out.txt`

{{< code language="python" title="discreteAddarithm.py" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
#!/usr/bin/python3

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.number import getPrime, getRandomInteger, getRandomRange
from Crypto.Protocol.KDF import HKDF
import Crypto.Hash.SHA512 as sha512
import Crypto.Cipher.AES as aes
from Crypto.Util.Padding import pad, unpad
from binascii import * 
from cybearssecrets import flag

def generateParameters(bitlen=1024):
	p = getPrime(bitlen)
	gen = getRandomRange(2,p-1)
	return gen, p

def generateKeyPair(p, gen):
	privateKey = getRandomRange(2,p-1)
	publicKey = privateKey*gen % p
	return privateKey, publicKey

def generateSharedSecret(p, recipientPrivateKey, senderPublicKey):
	sharedSecret = recipientPrivateKey*senderPublicKey % p
	return sharedSecret

## Init
gen, p = generateParameters()
print("gen = {}".format(gen))
print("p = {}".format(p))

## A: Alice generates her pub/priv key pair
aPrivateKey, aPublicKey = generateKeyPair(p, gen)

## B: Bob generates his pub/priv key pair
bPrivateKey, bPublicKey = generateKeyPair(p, gen)

## A: Alice sends Bob her public key
print("aPublicKey = {}".format(aPublicKey))

## B: Bob sends Alice his public key
print("bPublicKey = {}".format(bPublicKey))

## A: Alice caluculates the shared secret
aSharedSecret = generateSharedSecret(p, aPrivateKey, bPublicKey)

## B: Bob caluculates the shared secret
bSharedSecret = generateSharedSecret(p, bPrivateKey, aPublicKey)

## Prove that they match
assert(aSharedSecret == bSharedSecret)

## A: Alice encrypts a message to Bob
aSessionKey, aIV = HKDF(long_to_bytes(aSharedSecret), 16, b'cybears2024', sha512, num_keys=2)
a = aes.new(aSessionKey, aes.MODE_CBC, iv=aIV)
aCipher = a.encrypt(pad(flag,16))

print("aCipher = {}".format(hexlify(aCipher)))

## B: Bob decrypts the message
bSessionKey, bIV = HKDF(long_to_bytes(bSharedSecret), 16, b'cybears2024', sha512, num_keys=2)
b = aes.new(bSessionKey, aes.MODE_CBC, iv=bIV)
bPlain = unpad(b.decrypt(aCipher), 16)

if (bPlain == flag):
	print("Successful decryption!") 
else:
	print("Error - something went wrong")
{{< /code >}}

{{< code language="text" title="out.txt" expand="Show" collapse="Hide" isCollapsed="true" >}}
gen = 107665309954437515284050955368964848368303288172119448977068684165707548536106035934408882308704533335892101447750709116199826328820028967921540045634698373851938861013761725712688725891129665455073194344098566187055873775659411023106521425479072045658166413360399757570409372209072730576562842193768242314124
p = 154305601419430130125267211117098923915333624355567046250094074039674228187186943601303157833374662739969026864299363336407319080223107540886546467388611809417774875857578639486137855088896821184616399750557477866148643263803196632154429856293530179926011705130915364080130059881980341409627009701357523451267
aPublicKey = 80354936104370249925868492705190743680652231716704224547570074631753287352078443184923555333860525866848256788314156023903492043171511797029693297228294483818872563765707539175061570839714448005871291987391648926205060807957012526950116361633119573934316064444374124669861697695772912934202842834007697535925
bPublicKey = 42387482047117421466928118692687568439415997629141048723182072767997284324764640343272008345119819287526375581385721174494274510726524360731480638585425669685247170958054446797249761744238847427213615385731375648168698821769635116850680245545304663686514311913787022427877096835277158288159213482962236809739
aCipher = b'618fa12c3a6a6956a47a91bec13f9e1fe2d1031ba2f40a42b4f4d1d9757d0195ea6215fd694c2b99cf9a00be97b46791'
Successful decryption!
{{< /code >}}


It is essentially [Diffie Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange), but with multiplication instead of exponentiation:

- $p$ is a random 1024-bit prime
- $g$ (`gen`) is a random integer from $2$ to $p-1$
- Alice generates her private key $a$ and computes her public key $A = a \times g \bmod{p}$
- Bob generates his public key $b$ and computers his public key $B = b \times g \bmod{p}$
- We are given $p$, $g$, $A$ and $B$
- The shared secret $s$ is calculated such that $s = A \times b = a \times g \times b = B \times a \bmod{p}$, and used as an AES key to encrypt the flag.

Diffie Hellman leverages the discrete logarithm problem to make retrieving the private key from the public key difficult. However, in this challenge, multiplication is used instead of exponentiation to compute the public key, as $A = a \times g \bmod{p}$ instead of $A = a^g \bmod{p}$. 

Therefore, we can simply rearrange for the private key $a = A \times g^{-1} \bmod{p}$, then calculate the shared secret $s = a \times B \bmod{p}$, and decrypt the flag using the shared secret as the AES key.

{{< code language="python" title="code.py" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Protocol.KDF import HKDF
import Crypto.Hash.SHA512 as sha512
import Crypto.Cipher.AES as aes

# values
g = 107665309954437515284050955368964848368303288172119448977068684165707548536106035934408882308704533335892101447750709116199826328820028967921540045634698373851938861013761725712688725891129665455073194344098566187055873775659411023106521425479072045658166413360399757570409372209072730576562842193768242314124
p = 154305601419430130125267211117098923915333624355567046250094074039674228187186943601303157833374662739969026864299363336407319080223107540886546467388611809417774875857578639486137855088896821184616399750557477866148643263803196632154429856293530179926011705130915364080130059881980341409627009701357523451267
A = 80354936104370249925868492705190743680652231716704224547570074631753287352078443184923555333860525866848256788314156023903492043171511797029693297228294483818872563765707539175061570839714448005871291987391648926205060807957012526950116361633119573934316064444374124669861697695772912934202842834007697535925
B = 42387482047117421466928118692687568439415997629141048723182072767997284324764640343272008345119819287526375581385721174494274510726524360731480638585425669685247170958054446797249761744238847427213615385731375648168698821769635116850680245545304663686514311913787022427877096835277158288159213482962236809739
enc =  bytes.fromhex('618fa12c3a6a6956a47a91bec13f9e1fe2d1031ba2f40a42b4f4d1d9757d0195ea6215fd694c2b99cf9a00be97b46791')

# solve
a = (A * pow(g, -1, p)) % p
s = (a * B) % p

aSessionKey, aIV = HKDF(long_to_bytes(s), 16, b'cybears2024', sha512, num_keys=2)
a = aes.new(aSessionKey, aes.MODE_CBC, iv=aIV)
flag = a.decrypt(enc)
print(f"{flag = }")
{{< /code >}}

Flag: `cybears{C3rt41nly_ADDS_s0m3_pr0bl3ms}`

# Psionic - 10 solves

> The cybears face a door with a large wooden face carved into it. Surprisingly, the face starts moving and speaking! "Speak the password to enter" booms the door... the cybears consider their options..
> 
> `nc psionic.chal.cybears.io 2323`

This was a really weird challenge. We are given server code and an instance to connect to:

{{< code language="python" title="server.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
#!/usr/bin/python3

from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes, getRandomInteger, getPrime
import ast
import sys
import json

# This cybears.py file is not included in the handout.
# If you'd like to test locally, create a cybears.py file and put sensible variables in there
from cybears import secret_password, secret_password_chars, flag

# Server-client authentication protocol, but utilising Private-Set-Intersection
# Based on https://csrc.nist.gov/CSRC/media//Projects/pec/documents/stppa-02-PSI-rosulek.pdf

# Client ------------- Server
# 1. {H(p1)^a, H(p2)^a ... } -> 
# 2.               <- {H(s1)^b, H(s2)^b, ..., H(p1)^a^b, H(p2)^a^b... }
# 3. {H(s1)^b^a, H(s2)^b^a, ...} 
# 4. Client checks whether any of the H(s_i)^b^a == H(p_j)^a^b
# 5. Server does same
# 6. If all p_i == s_j, allow client to submit H(nonce || password) for flag! 


def validate_client(client1): 
    result = False
    output = {}

    # parse input 
    try:
        c = ast.literal_eval(client1)
    except Exception as e: 
        print("Incorrect format - must be a list of integers")
        return result, output    

    # Check that we have a set
    if type(c) != list: 
        return result, output

    # Check that all elements in the list are integers
    if all(list(map(lambda x: type(x) == int, c))) != True: 
        return result, output

    result = True
    output = c
    return result, output 


if __name__ == "__main__":

    # Generate ephemeral server public/private keys
    generator = 2
    public_prime = getPrime(1024)
    server_private = getRandomInteger(1024)
    server_public = pow( 2, server_private, public_prime)
    params = { "prime" : public_prime, "generator": generator, "server_public" : server_public } 
    


    print("Welcome to the psionic login server!")
    print("params = {}".format(json.dumps(params)))
    print("Please enter your set of passwords and we will confirm there is a match:")

    # 1. client to send commitment
    client1 = input() #expect single string of len(password) entries as a list
    
    result, output = validate_client(client1)
    if result == False: 
        print("Incorrect format - must be a list of integers")
        sys.exit(-1)
    
    if len(output) != len(secret_password):
        print("Incorrect length - must same length as password")
        sys.exit(-1)
        
    # 2. server to send commitment
    server_response1 = list(map(lambda x : pow(x, server_private, public_prime), output))
    server_response2 = list(map(lambda x : pow(bytes_to_long(sha1(x.encode()).digest()), server_private, public_prime), secret_password_chars))
    print("{}".format(server_response1 + server_response2))

    # 3. client to send verification
    client2 = input() #expect single string of len(password) entries as a list

    result2, output2 = validate_client(client2)
    if result2 == False:
        print("Incorrect format - must be a list of integers")
        sys.exit(-1)

    if len(output2) != len(secret_password):
        print("Incorrect length - must same length as password")
        print("DEBUG: {} / {}".format( len(output), len(secret_password)))
        sys.exit(-1)

    # 5. Server validation - confirm that { H(p_i)^b^a } == {H(s_i)^a^b}
    # Client could just replay, but we don't just accept this as proof of knowing the password! 
    print("checking...")
    
    if (set(output2) == set(server_response1)): 
        print("Sets are a match! You must know the password!") 
        print("Send it through") # TODO, hash with a nonce? 
        
        client_password = input()
        if(client_password == secret_password): 
            print("Correct! Here is your flag: {}".format(flag))
            sys.exit(0)
        else: 
            print("Incorrect password")
            sys.exit(-1)
    else:
        print("Set mismatch. You don't know the password!")
        sys.exit(-1)
{{< /code >}}

It's supposedly some sort of "Private Set Intersection" (PSI), where we need to provide integers (being characters of the password), and it will tell us how many of those are part of the password, and we provide the full password to get the flag.

Lets step through the server code:
- First, we're provided with some parameters, a prime $p$, generator $g$ and server public value $v = g^y \bmod{p}$ where $y$ is the server private value (These turn out to be useless, so we can kind of just ignore this).
- Next, it prompts us for a list of integers $X = \\{x_0, x_1, ..., x_n\\}$, and the list must be the same length as the password
- It then loops through the list of integers $X$ and computes $H_X = x_n^y \bmod{p}$ for each item $x_n$ in our list $X$, where H(x) is the SHA1 hash function.
- It does a similar operation for the password chars, computing $H_Z = H(z_n)^y \bmod{p}$ for each character $z_n$ in the password $Z$.
- It sends us both $H_X$ and $H_Z$, which are "hidden", hashed values used to compute the private set intersection.
- We are prompted again to provide another list of integers, and the server will check if this list is equal to $H_X$. This step doesn't really make sense since the server sends us $H_X$, so all we have to do is repeat it back.
- If equal, we will be prompted to enter the password as a string, and if the password is correct, we get the flag.

The code really confused me as I wasn't sure what the challenge was here. I looked at the [link provided in the code](https://csrc.nist.gov/CSRC/media//Projects/pec/documents/stppa-02-PSI-rosulek.pdf) which was an overview on Private Set Intersection, and saw that just hashing elements of the set was bad for PSI.

{{< image src="./img/bad_psi.png" alt="" position="center" style="border-radius: 5px; width: 70%" >}}

This is because the point of a private set intersection is for two parties, each with their own private set of data, to compute the intersection between the two sets, **without** either party learning about the whole private set of the other.

One (bad) way to do this is for you to hash all elements of your set, and the other party does the same. Then you can compare hashed elements - as identical elements hash to the same digest, you can perform PSI by computing the intersection between sets containing the hashed elements. But the link mentions this is a bad way to do it, because you can use a dictionary attack, hashing all possible values of elements in the set, and comparing it to the hash digest of the other party, learning about their elements if hash digests match.

However, the server seems to mitigate this - recall that our "hidden" set is $H_X = x_n^y \bmod{p}$, and we don't know the server private value $y$, so we cannot compute this ourselves. But almost the same method is used to generate the password, $H_Z = H(z_n)^y \bmod{p}$, and the server sends us both these sets. Therefore, we can send $X = \\{H("a"), H("b"), ...\\}$ and the server will compute $H_X = x_n^y \bmod{p}$ which will be $\\{H("a")^y, H("b")^y, ...\\}$, and we can compute this set to the password set which will be $\\{H(z_0)^y, H(z_1)^y, ..., H(z_n)^y\\}$ and intersect these two sets. An element in both these sets reveals a character of the password.

The server imports the secret password and password chars:
```py
# This cybears.py file is not included in the handout.
# If you'd like to test locally, create a cybears.py file and put sensible variables in there
from cybears import secret_password, secret_password_chars, flag
```

I assumed `cybears.py` would look something like this:
```py
secret_password = "1234567890!"
secret_password_chars = list(secret_password)
flag = "cybears{testing}"
```

But after my solve script worked local but not on remote, I asked the challenge author if `secret_password` and `secret_password_chars` were constnat on the server. As it turns out, while `secret_password` is constant, `secret_password_chars` is not - it's scrambled! Which means `cybears.py` probably looks something like this:
```py
import random
secret_password = "1234567890!"
secret_password_chars = random.shuffle(list(secret_password))
flag = "cybears{testing}"
```
Knowing this, I came up with the solution:
- Brute force a little bit to get the password length (server will error if provided integer list not same length as password), which turned out to be 11
- Check what characters were in the password, by sending integers from 0 to 255, 11 at a time, and intersecting the sets returned from the server. Technically, the sets returned by the server were lists, so we can note the indexes of elements that intersected to know which character is in the password.
- Attempt to unscramble the characters to form a password, such as by using an anagram solver.
- Submit password and get the flag.

I found it really weird that I had to unscramble the password, it didn't seem to make sense that `secret_password_chars` was scrambled, as otherwise, you could easily correlate the indexes of intersecting elements to know what character is in what position. My best guess for why it was scrambled would be that the challenge author wanted to simulate the unordered nature of sets. If anyone knows why, please let me know!

After running a script to get all the chars, we get characters `['!', '1', 'A', 'g', 'h', 'i', 'l', 'm', 'o', 'r', 't']`. Convering some from l33t c0d3 and putting it in an anagram solver, we get `Algorithm` as a potential word. Then we can start to guess passwords, and the correct one turns out to be `Algorithm1!`, which gets us the flag.

Solve scripts:

{{< code language="python" title="get_pw_chars.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
from pwn import *
from Crypto.Util.number import *
import json
import string
from hashlib import sha1

pw_chars = []

step = 11
for i in range(0, 256, step):
    r = remote("psionic.chal.cybears.io", 2323)
    # r = remote("localhost", 1111)

    r.recvline()
    r.recvuntil(b"params = ")
    params = json.loads(r.recvline().strip().decode()) # unused
    r.recvuntil(b" match:")
    
    arr_raw = [chr(v) for v in range(i, i+step)]
    arr = [bytes_to_long(sha1(v.encode()).digest()) for v in arr_raw]

    r.sendline(str(arr).encode())
    r.recvline()

    resp = eval(r.recvline().strip().decode())
    H_X, H_Y = resp[:11], resp[11:]

    for xi, x in enumerate(H_X):
        for yi, y in enumerate(H_Y):
            if x == y:
                pw_chars.append(arr_raw[xi])

print(f"{pw_chars = }")

{{< /code >}}

{{< code language="python" title="get_flag.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
from pwn import *
from Crypto.Util.number import *
import json
import string
from hashlib import sha1

pw_chars = []
r = remote("psionic.chal.cybears.io", 2323)
# r = remote("localhost", 1111)

r.recvline()
r.recvuntil(b"params = ")
params = json.loads(r.recvline().strip().decode()) # unused
r.recvuntil(b" match:")

arr_raw = [chr(v) for v in range(0, 11)]
arr = [bytes_to_long(sha1(v.encode()).digest()) for v in arr_raw]

r.sendline(str(arr).encode())
r.recvline()

resp = eval(r.recvline().strip().decode())
H_X, H_Y = resp[:11], resp[11:]

r.sendline(str(H_X).encode())

r.sendline(b"Algorithm1!")
r.interactive()

{{< /code >}}

Flag: `cybears{n0t_s0_pr1v@t3_int3rs3ct10n}`

This was a unique challenge, different to most crypto chals, but I didn't really like having to guess the password from a set of characters - I thought that was a bit guessy and I was lucky to have guessed it.

# Public Service - 8 solves

> You find a parchment filled with ancient writings. At the bottom are a number of ornate calligraphic signatures...

This was a nice challenge. We're given two files, `generate_signatures.py` and `out.json`:

{{< code language="python" title="generate_signatures.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
import Crypto.Signature.DSS as dss
import Crypto.PublicKey.ECC as ecc
import Crypto.Hash.SHA256 as sha256
import Crypto.PublicKey.RSA as rsa
import Crypto.Signature.PKCS1_v1_5 as pkcs
import Crypto.Cipher.PKCS1_OAEP as oaep
from Crypto.Util.number import inverse, getPrime, isPrime, long_to_bytes, bytes_to_long
from binascii import hexlify
import json

from cybearssecrets import FLAG

MESSAGE1 = b'If a new source of energy is not found, no one is going to win this war'
MESSAGE2 = b'Bah weep gragnah weep nini bong'
MESSAGE3 = b'Freedom is the right of all sentient beings'

## Generate Elliptic Curve parameters
ec = ecc.generate(curve = "p256")
ec_signer = dss.new(ec, 'fips-186-3')

## Generate Elliptic Curve Signature
ec_hasher = sha256.new(MESSAGE1)
ec_sig = ec_signer.sign(ec_hasher)

## Generate RSA parameters
def generate_special_prime(b):
    t = bytes_to_long(b)
    while not(isPrime(t)):
        t += 1
    return t

rsa_p = generate_special_prime(long_to_bytes(ec.pointQ.x)+long_to_bytes(ec.pointQ.y))
rsa_q = getPrime(512) 

rsa_n = rsa_p*rsa_q
rsa_e = 65537
rsa_d = inverse(rsa_e, (rsa_p-1)*(rsa_q-1))

r = rsa.construct((rsa_n,rsa_e,rsa_d))

## Generate RSA Signatures
rsa_signer = pkcs.new(r)

rsa_hasher1 = sha256.new(MESSAGE2)
rsa_hasher2 = sha256.new(MESSAGE3)

rsa_sig1 = rsa_signer.sign(rsa_hasher1)
rsa_sig2 = rsa_signer.sign(rsa_hasher2)

## Encrypt Flag
encrypter = oaep.new(r)
cipher = encrypter.encrypt(FLAG)

j = {}
j['ec_sig'] = hexlify(ec_sig).decode()
j['rsa_sig1'] = hexlify(rsa_sig1).decode()
j['rsa_sig2'] = hexlify(rsa_sig2).decode()
j['cipher'] = hexlify(cipher).decode()

with open("out.json", "w") as g: 
    g.write(json.dumps(j))

{{< /code >}}

{{< code language="json" title="out.json" expand="Show" collapse="Hide" isCollapsed="true" >}}
{"ec_sig": "8d32a95ab9b4d92f6ff307d9721451707822d2eae3e07c5c605f0d5979a2e2210b5149487c4d1bedafa96628fcc3579b4842abfa156a963d7db0c15d8da32cc9", "rsa_sig1": "45e225f7532b25aa283f80b5166de185cff8b46fb3c9de982083b1ed4a7621c14d0ab541e945c31c9984f958d0b23331d6c636ba8c443941afa277dd2b00c9b7884b4bc9a55047b77305cc6061d9aa9e6be99b70f2f469f6c1accba77228ef129af79bb7f196176753ed27f8308a30b298c34bfc3503dce92f77f0ed8b6d16b6", "rsa_sig2": "56b9bac062a9a75b2db42b480e439927265a06b0815be14814f19cd27553a8bdd2815c1814a060fa25b9713b10516b57c9e1f399415492f1ac9a8795034ade99744237a6354d32c0e7330b0b0f52d237e7967863869cf9fdc387f90349c9fbffa15aa72c48ece92bbe59760f41606bfff28af9fdde8f275bf07379f798d98d4d", "cipher": "65312f30ef4f34edd32c11ce885c51279bdecd16168953733f04380eb1ed183542e745d630133c4c0c5ce7580bbfb90a347c387eb2743ffaeae5cb7a82058e0fb8a85f7aa392433dc12f0b78e9e0b577909353de84913a47895109de2019a3b88b72f03e13b16f7b092e7a428c664ed174b2cb63208b7a55e9d02a2c0f268d4e"}
{{< /code >}}

There are 3 known, plaintext messages, $m_1$, $m_2$, and $m_3$. A p256 curve is used and a private key on the curve is generated. Then, a ECDSA signature is created from signing the sha256 hash of $m_1$. We are given this signature.

Next, a prime $p$ is deterministically generated, using the public key on the curve, point $Q$. Then standard RSA follows, generating prime $q$, public key $n=pq$, and private key $d=e^{-1} \bmod(\phi{(n)})$. Signatures of $m_2$ and $m_3$ are created using the RSA private key, and we are given these signatures. The flag is then encrypted with the RSA key, and we are given the encrypted flag.

The challenge is to recover both the ECC and RSA public keys, and decrypt the flag.

### Recovering ECC Public Key

I searched online for recovering the public key from an ECDSA signature and found [this](https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work), which you should read for more details, but essentially you can recover the public key given a signature $(r, s)$, by finding the two points $R$ and $\prime{R}$ with the same x coordinate as $r$, and calculating:

$$
r^{-1}(sR - zG) \newline
r^{-1}(s\prime{R} - zG)
$$

where $z$ is the message that was signed, and $G$ is the generator on the curve. As shown above this yields two points, one of which is the public key $Q$.

We can do so using the sage code:
```py
# p-256 curve paramters from https://neuromancer.sk/std/nist/P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff 
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)

r,s = bytes_to_long(ec_sig[:32]), bytes_to_long(ec_sig[32:])
z = bytes_to_long(MSG1_HASH.digest())

r_inv = pow(r, -1, E.order())
R, R_ = E.lift_x(K(r), all=True)

Q_1 = r_inv * (s*R - z*G)
Q_2 = r_inv * (s*R_ - z*G)
```


### Recovering RSA Public Key

We have two messages $m_2$ and $m_3$ that are signed with RSA, yielding $s_2$ and $s_3$. Searching online again I found [this](https://crypto.stackexchange.com/questions/26188/rsa-public-key-recovery-from-signatures) which states you can recover public modulus $n$ by computing $\gcd{\(s_2^e - m_2, s_3^e - m_3\)} = kn$ where $k$ is small.

This makes sense as $m_2 = s_2^e \bmod{n}$ thus $m_2 = s_2^e - k_2n$ for some integer $k_2$, therefore we can GCD $m_2 - s_2^e = -k_2n$ and $m_3 - s_3^e = -k_3n$ to obtain a multiple of $n$.

As $e = 65537$, this takes a while to compute, but after doing so we recover (a multiple of) the public modulus $n$.

Note that $m_2$ is actually a transformed version of the plaintext message, as it is first hashed then some pkcs1_15 scheme is used to pad the message. This made it really annoying to get the message that was actually signed, so I directly edited the library code to print the message being signed, and ran the challenge script with a test flag.

{{< image src="./img/get_real_m.png" alt="" position="center" style="border-radius: 5px; width: 70%" >}}

### Getting the flag

Now that we have both the ECDSA and RSA pubkey, we can recover the flag. As mentioned before, one of the RSA primes are generated deterministically based on the ECDSA pubkey $Q$:

```python
def generate_special_prime(b):
    t = bytes_to_long(b)
    while not(isPrime(t)):
        t += 1
    return t

rsa_p = generate_special_prime(long_to_bytes(ec.pointQ.x)+long_to_bytes(ec.pointQ.y))
```

So now that we recovered the pubkey, we can simply call this function to recover a prime. Even though we have 2 possible ECDSA pubkeys, we can check which one is correct by generating the 2 possible primes and using GCD with $n$.

From there, it's just simple RSA to generate the RSA private key and decrypt the flag.

Solve script:
{{< code language="python" title="code.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
import Crypto.Hash.SHA256 as sha256
import Crypto.PublicKey.RSA as rsa
import Crypto.Cipher.PKCS1_OAEP as oaep
from Crypto.Util.number import *

## Generate RSA parameters
def generate_special_prime(b):
    t = bytes_to_long(b)
    while not(isPrime(t)):
        t += 1
    return t

data = {"ec_sig": "8d32a95ab9b4d92f6ff307d9721451707822d2eae3e07c5c605f0d5979a2e2210b5149487c4d1bedafa96628fcc3579b4842abfa156a963d7db0c15d8da32cc9", "rsa_sig1": "45e225f7532b25aa283f80b5166de185cff8b46fb3c9de982083b1ed4a7621c14d0ab541e945c31c9984f958d0b23331d6c636ba8c443941afa277dd2b00c9b7884b4bc9a55047b77305cc6061d9aa9e6be99b70f2f469f6c1accba77228ef129af79bb7f196176753ed27f8308a30b298c34bfc3503dce92f77f0ed8b6d16b6", "rsa_sig2": "56b9bac062a9a75b2db42b480e439927265a06b0815be14814f19cd27553a8bdd2815c1814a060fa25b9713b10516b57c9e1f399415492f1ac9a8795034ade99744237a6354d32c0e7330b0b0f52d237e7967863869cf9fdc387f90349c9fbffa15aa72c48ece92bbe59760f41606bfff28af9fdde8f275bf07379f798d98d4d", "cipher": "65312f30ef4f34edd32c11ce885c51279bdecd16168953733f04380eb1ed183542e745d630133c4c0c5ce7580bbfb90a347c387eb2743ffaeae5cb7a82058e0fb8a85f7aa392433dc12f0b78e9e0b577909353de84913a47895109de2019a3b88b72f03e13b16f7b092e7a428c664ed174b2cb63208b7a55e9d02a2c0f268d4e"}

MESSAGE1 = b'If a new source of energy is not found, no one is going to win this war'
MSG1_HASH = sha256.new(MESSAGE1)

ec_sig = bytes.fromhex(data["ec_sig"])
s1 = int(data["rsa_sig1"], 16)
s2 = int(data["rsa_sig2"], 16)
enc_flag = bytes.fromhex(data["cipher"])

# p-256 curve paramters from https://neuromancer.sk/std/nist/P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff 
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)

# part 1: recover ECC public key
r,s = bytes_to_long(ec_sig[:32]), bytes_to_long(ec_sig[32:])
z = bytes_to_long(MSG1_HASH.digest())

r_inv = pow(r, -1, E.order())
R, R_ = E.lift_x(K(r), all=True)

Q_1 = r_inv * (s*R - z*G)
Q_2 = r_inv * (s*R_ - z*G)

print(f"Recovered possible ECSDA pubkeys:")
print(f"{Q_1 = }")
print(f"{Q_2 = }")

# part 2: recover RSA public key

e = 65537
# values from editing library src and printing msg before it got signed
# MESSAGE2 = b'Bah weep gragnah weep nini bong'
# MESSAGE3 = b'Freedom is the right of all sentient beings'
m2 = 5486124068793688683255936251187209270074392635932332070112001988456197381759672947165175699536362793613284725337872111744958183862744647903224103718245670299614498700710006264535421091908069935709303403272242499531581061652193706559968553759421347924920266204277973339410586176390872847811111144114590842
m3 = 5486124068793688683255936251187209270074392635932332070112001988456197381759672947165175699536362793613284725337872111744958183862744647903224103718245670299614498700710006264535421091908069935709303403272242499531581061652193643492425095701346333448554897794580398627955585138706133687412101835882486651

print(f"Recovering RSA pubkey...")

kn = gcd(s1^e - m2, s2^e - m3)

print(f"Recovered RSA pubkey multiple {kn = }")

# last part: decrypting flag

rsa_p_1 = generate_special_prime(long_to_bytes(int(Q_1.x()))+long_to_bytes(int(Q_1.y())))
rsa_p_2 = generate_special_prime(long_to_bytes(int(Q_2.x()))+long_to_bytes(int(Q_2.y())))

p = None
if gcd(rsa_p_1, kn) != 1:
    p = rsa_p_1
elif gcd(rsa_p_2, kn) != 1:
    p = rsa_p_2
else:
    print("Something went wrong, neither primes are correct")

# k*n = k*p*q
kq = kn // p
# get largest factor of kq which should be q
q = list(dict(factor(kq)).keys())[-1]

n = p*q
d = pow(e, -1, (p-1)*(q-1))

r = rsa.construct((int(n),int(e),int(d)))
decrypter = oaep.new(r)
flag = decrypter.decrypt(enc_flag)
print(f"{flag = }")

{{< /code >}}

Flag: `cybears{D0nt_m4k3_pr1v4t3_publ1c_k3yz!}`


# arpeeceethree - 3 solves

> You hand over your identity parchment to the temple monk. He scrutinises it closely, looking for any signs of malintent.
> 
> `python client.py -r arpeeceethree.chal.cybears.io:2323`

There was a lot of source and dependencies to install for this challenge, but the vulnerability is actually very simple.

We are provided with 3 files, `client.py`, `server.py` and `server.proto`.

{{< code language="python" title="client.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
from pwn import * 
from google.protobuf.internal.encoder import _VarintEncoder
from google.protobuf.internal.decoder import _DecodeVarint
import server_pb2 as spb
from google.protobuf.internal.decoder import _DecodeError
import sys 
import argparse

import Crypto.Cipher.AES as AES
import Crypto.Hash.SHA512 as SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes, bytes_to_long

from ecdsa import ECDH, NIST256p, VerifyingKey


def send_message(s, msg):
    """ Send a message, prefixed with its size, to a TPC/IP socket """
    data = msg.SerializeToString()
    mh = spb.MessageHeader()
    mh.msglen = len(data)
    mh.type = msg.type
    s.send(mh.SerializeToString() + data)
    return 

def msg_type(msgtype):
    if msgtype == spb.MSG_LOGIN_REQUEST:
        return spb.LoginRequest()
    elif msgtype == spb.MSG_LOGIN_RESPONSE:
        return spb.LoginResponse()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE:
        return spb.LoginChallenge()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE_RESPONSE:
        return spb.LoginChallengeResponse()
    elif msgtype == spb.MSG_REGISTER_REQUEST:
        return spb.RegisterRequest()
    elif msgtype == spb.MSG_REGISTER_RESPONSE:
        return spb.RegisterResponse()
    elif msgtype == spb.MSG_MESSAGE_REQUEST:
        return spb.MessageRequest()
    elif msgtype == spb.MSG_MESSAGE_RESPONSE:
        return spb.MessageResponse()
    else:
        return None


def check_fields(msg):
    result = True
    for field in msg.DESCRIPTOR.fields_by_name.keys():
        if msg.DESCRIPTOR.fields_by_name[field].label == msg.DESCRIPTOR.fields_by_name[field].LABEL_REQUIRED:
            result &= msg.HasField(field)
    return result

def recv_message(s):
    """ Receive a message, prefixed with its size and type, from stdin """
    # Receive the size of the message data
    # expect [MessageHeader][Message of type]
    data = b''
    header = spb.MessageHeader()
    while True:
        data+= s.recv(1)
        try:
            header.ParseFromString(data)
            if check_fields(header):
                break
        except _DecodeError as e:
            pass

    # Receive the message data
    data = s.recv(header.msglen)

    # Decode the message and validate all required fields are present
    msg = msg_type(header.type)
    if msg != None:
        try:
            msg.ParseFromString(data)
            if not check_fields(msg):
                return None
            return msg
        except _DecodeError:
            return None
    else:
        return None

def create_user():
    client_ecdh = ECDH(curve=NIST256p)
    client_ecdh.generate_private_key()
    return client_ecdh

def register(s, ecdh, name=b'bumblebear', pubkey=b''):
    ## REGISTER
    rr = spb.RegisterRequest()
    rr.type = spb.MSG_REGISTER_REQUEST
    rr.name = name
    if pubkey == b'':
        rr.clientPublicKey = ecdh.get_public_key().to_string(encoding='compressed')
    else:
        rr.clientPublicKey = pubkey

    send_message(s, rr)

    ## REGISTER RESPONSE
    reg_resp = recv_message(s)
    if reg_resp != None:
        log.info("DEBUG: received {}".format(reg_resp))
    if reg_resp.status == spb.FAILURE:
        log.error("failed to register")
    uid = reg_resp.uid
    return uid

def login(s, uid):
    ## LOGIN
    l = spb.LoginRequest()
    l.type = spb.MSG_LOGIN_REQUEST
    l.uid = uid
    send_message(s, l)

    ## LOGIN RESPONSE
    login_resp = recv_message(s)
    if login_resp != None:
        log.info("DEBUG: received {}".format(login_resp))
    
    return login_resp.sessionId, login_resp.challenge, login_resp.ephemeralServerPublicKey


def login2(s, ecdh, sessionId, challenge):
    ## SIGN CHALLENGE
    sig = ecdh.private_key.sign_deterministic(challenge)

    ## GENERATE EPHEMERAL DH SESSION KEY
    client_ephemeral_ecdh = ECDH(curve=NIST256p)
    client_ephemeral_ecdh.generate_private_key()
    client_ephemeral_public_key = client_ephemeral_ecdh.get_public_key()

    send_chal = spb.LoginChallenge()
    send_chal.type = spb.MSG_LOGIN_CHALLENGE
    send_chal.sessionId = sessionId
    send_chal.ephemeralClientPublicKey = client_ephemeral_public_key.to_string(encoding='compressed')

    send_chal.challengeResponse = sig
    send_message(s, send_chal)

    msg_resp = recv_message(s)
    if msg_resp != None:
        log.info("DEBUG: received {}".format(msg_resp))

    return client_ephemeral_ecdh

def request_msg(s, sessionId, uid, client_ephemeral, server_ephemeral):
    ## REQUEST MESSAGE
    log.info("sending message request")
    msg_req = spb.MessageRequest()
    msg_req.type = spb.MSG_MESSAGE_REQUEST
    msg_req.sessionId = sessionId

    send_message(s, msg_req)

    log.info("receiving message")
    msg_resp = recv_message(s)
    if msg_resp != None:
        log.info("DEBUG: received {}".format(msg_resp))

    ## DECRYPT MESSAGE
    server_ephemeral_public_key = VerifyingKey.from_string(server_ephemeral, NIST256p)

    client_ephemeral.load_received_public_key(server_ephemeral_public_key)
    shared_secret = client_ephemeral.generate_sharedsecret_bytes()

    token  = shared_secret
    token += b'|' + long_to_bytes(spb.USER)
    token += b'|' + long_to_bytes(uid)
    token += b'|' + sessionId
    (aes_gcm_key, nonce) = HKDF(token, 16, '', SHA512, num_keys=2)

    a = AES.new(aes_gcm_key, AES.MODE_GCM, nonce = nonce)
    message = a.decrypt_and_verify(msg_resp.encMsg, msg_resp.encMsgTag)

    log.info("message received: {}".format(message))
    return message

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--remote', help="The address:port of the remote server hosting the challenge", required=True)
    args = parser.parse_args()

    if args.remote != None:
        host = args.remote.split(":")[0]
        port = int(args.remote.split(":")[1])
    else:
        exit(0)

    s = remote(host, port)

    ## Create new user
    log.info("Creating new user")
    e = create_user()

    ## Register
    log.info("Registering new user")
    uid = register(s,e)

    ## Login
    log.info("Logging in - part 1")
    (sessionId, chal, sepk) = login(s, uid)
    log.info("Logging in - part 2")
    ceph = login2(s, e, sessionId, chal)

    ## Request message
    log.info("Requesting message")
    msg = request_msg(s, sessionId, uid, ceph, sepk)
    log.info("message received: {}".format(msg))


    s.close()
{{< /code >}}


{{< code language="python" title="server.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
#!/usr/bin/python3

# protoc -I=. --python_out=. ./server.proto
# socat -d TCP-LISTEN:2323,reuseaddr,fork EXEC:"python3 server_stdio_3.py"

from google.protobuf.internal.encoder import _VarintEncoder
from google.protobuf.internal.decoder import _DecodeVarint
import server_pb2 as spb
from google.protobuf.internal.decoder import _DecodeError

import Crypto.Cipher.AES as AES
import Crypto.Hash.SHA512 as SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes, bytes_to_long

from ecdsa import ECDH, NIST256p, VerifyingKey
import uuid

import logging
import os
import sys

from cybears import flag

#logging.root.setLevel(logging.DEBUG)
#logging.root.setLevel(logging.INFO)
logging.root.setLevel(logging.ERROR)

logger = logging.getLogger("__name__")

h1 = logging.StreamHandler(sys.stderr)
h1.setLevel(logging.DEBUG)
h2 = logging.StreamHandler(sys.stderr)
h2.setLevel(logging.INFO)

logger.addHandler(h1)
logger.addHandler(h2)


def send_message(msg):
    """ Send a message, prefixed with its size, to stdout """
    data = msg.SerializeToString()
    mh = spb.MessageHeader()
    mh.msglen = len(data)
    mh.type = msg.type
    sys.stdout.buffer.write(mh.SerializeToString() + data)
    sys.stdout.flush()
    logging.info("Sent msg over stdout...")
    return 

def msg_type(msgtype):
    if msgtype == spb.MSG_LOGIN_REQUEST:
        return spb.LoginRequest()
    elif msgtype == spb.MSG_LOGIN_RESPONSE:
        return spb.LoginResponse()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE:
        return spb.LoginChallenge()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE_RESPONSE:
        return spb.LoginChallengeResponse()
    elif msgtype == spb.MSG_REGISTER_REQUEST:
        return spb.RegisterRequest()
    elif msgtype == spb.MSG_REGISTER_RESPONSE:
        return spb.RegisterResponse()
    elif msgtype == spb.MSG_MESSAGE_REQUEST:
        return spb.MessageRequest()
    elif msgtype == spb.MSG_MESSAGE_RESPONSE:
        return spb.MessageResponse()
    else:
        return None   

def check_fields(msg):
    result = True
    for field in msg.DESCRIPTOR.fields_by_name.keys():
        if msg.DESCRIPTOR.fields_by_name[field].label == msg.DESCRIPTOR.fields_by_name[field].LABEL_REQUIRED:
            result &= msg.HasField(field)
    return result

def recv_message():
    """ Receive a message, prefixed with its size and type, from stdin """
    # Receive the size of the message data
    # expect [MessageHeader][Message of type]
    data = b''
    header = spb.MessageHeader()
    while True:
        data+= sys.stdin.buffer.read(1)
        try: 
            header.ParseFromString(data)
            if check_fields(header):
                break
        except _DecodeError as e: 
            pass
    logging.debug("header {}".format(header))

    # Receive the message data
    data = sys.stdin.buffer.read(header.msglen)
    logging.debug("received [{}]".format(data))

    # Decode the message and validate all required fields are present
    msg = msg_type(header.type)
    if msg != None: 
        try:
            msg.ParseFromString(data)
            if not check_fields(msg):
                return None
            logging.debug("msg {}".format(msg))
            return msg
        except _DecodeError:
            return None
    else:
        return None

def handle_register_request(msg):
    logging.debug("Got register request")
    # validate request
    # check public key is on correct curve
    try:
        v = VerifyingKey.from_string(msg.clientPublicKey, NIST256p)
    except Exception as e:
        resp = spb.RegisterResponse()
        resp.type = spb.MSG_REGISTER_RESPONSE
        resp.uid = 0xff
        resp.status = spb.FAILURE
        send_message(resp) 
        logging.info("FAILURE: User failed to registered with invalid pub key: {} and error {}".format(msg.clientPublicKey,e))
        return spb.FAILURE

    # parse request
    uid = register_user(USERS, msg.name, msg.clientPublicKey)

    # send response
    resp = spb.RegisterResponse()
    resp.type = spb.MSG_REGISTER_RESPONSE
    resp.uid = uid
    resp.status = spb.SUCCESS
    send_message(resp) 
    logging.info("SUCCESS: User registered with uid: {}".format(uid))

    return spb.SUCCESS

def handle_login_request(SESSION, msg):
    logging.debug("Got Login request")
    resp = spb.LoginResponse()
    resp.type = spb.MSG_LOGIN_RESPONSE

    # validate request
    if msg.uid > len(USERS) or msg.uid == 0: 
        logging.info("ERROR: invalid uid")
        resp.status = spb.FAILURE
        resp.sessionId = b''
        resp.challenge = b''
        resp.ephemeralServerPublicKey = b''
        send_message(resp)
        return spb.FAILURE

    requested_user = USERS[msg.uid - 1]

    # parse request
    
    # send response
    challenge = os.urandom(32) # random 32-byte challenge to sign    
    server_ephemeral_ecdh = ECDH(curve=NIST256p)
    server_ephemeral_ecdh.generate_private_key()
    server_ephemeral_public_key = server_ephemeral_ecdh.get_public_key()
    
    sessionId = str(uuid.uuid4()).encode()

    resp.status = spb.SUCCESS
    resp.sessionId = sessionId
    resp.challenge = challenge
    resp.ephemeralServerPublicKey = server_ephemeral_public_key.to_string(encoding='compressed')

    SESSIONS[sessionId] = {'completed_challenge':False, 'challenge':challenge, 'ephemeral_ecdh':server_ephemeral_ecdh, 'uid':msg.uid}
    logging.debug("New session created {}".format(SESSIONS[sessionId]))
    logging.info("SUCCESS: User correctly requested login with uid: {}".format(msg.uid))
    send_message(resp)

    return spb.SUCCESS

def verify_challenge(chal, chalResponse, public_key):

    try:
        public_key.verify(chalResponse, data=chal)
    except ecdsa.BadSignatureError:
        return False

    return True

def handle_login_challenge_request(SESSION, USERS, msg):
    logging.debug("Got Login Challenge request")
    resp = spb.LoginChallengeResponse()
    resp.type = spb.MSG_LOGIN_CHALLENGE_RESPONSE
        
    # validate request
        # sessionId in SESSIONS?
    if msg.sessionId not in SESSIONS:
        resp.status = spb.FAILURE
        resp.sessionId = b''
        logging.info("FAILURE: User send invalid sessionId: {}".format(msg.sessionId))
        send_message(resp)
        return spb.FAILURE

    uid = SESSIONS[msg.sessionId]['uid']
    requested_user = USERS[uid - 1]
    logging.debug("requested user {}: {}".format(uid,requested_user))
    clientPubKey = VerifyingKey.from_string(requested_user['pubkey'], NIST256p) #already validated 
    clientRole = requested_user['role']

    sessionId = msg.sessionId
        # verify challenge
    if not verify_challenge(SESSION[sessionId]['challenge'], msg.challengeResponse, clientPubKey):
        resp.status = spb.FAILURE
        resp.sessionId = b''
        logging.info("FAILURE: User failed challenge: {}".format(msg.challenge))
        send_message(resp)
        return spb.FAILURE

        # ensure ephem client key is on curve
    try:
        clientEphemPubKey = VerifyingKey.from_string(msg.ephemeralClientPublicKey, NIST256p)
    except Exception as e:
        resp.status = spb.FAILURE
        resp.sessionId = b''
        logging.info("FAILURE: Invalid client ephemeral public key: {}".format(msg.ephemeralClientPublicKey))
        send_message(resp)
        return spb.FAILURE

    # action request
    server_ephemeral_ecdh = SESSIONS[sessionId]['ephemeral_ecdh']
    server_ephemeral_ecdh.load_received_public_key(clientEphemPubKey)
    shared_secret = server_ephemeral_ecdh.generate_sharedsecret_bytes()

    token  = shared_secret 
    token += b'|' + long_to_bytes(clientRole) 
    token += b'|' + long_to_bytes(uid) 
    token += b'|' + sessionId

    # send response
    resp.status = spb.SUCCESS
    resp.sessionId = sessionId

    SESSIONS[sessionId]['completed_challenge'] = True
    SESSIONS[sessionId].update( {'client_token':token} )
    logging.info("SUCCESS: User correctly completed challenge with uid: {}".format(uid))
    send_message(resp)

    return spb.SUCCESS

def handle_message_request(SESSIONS, msg):
    logging.debug("Got message request")
    resp = spb.MessageResponse()
    resp.type = spb.MSG_MESSAGE_RESPONSE
    # validate request
    if msg.sessionId not in SESSIONS:
        resp.status = spb.FAILURE
        resp.encMsg = b''
        resp.encMsgTag = b''
        logging.info("ERROR: Invalid sessionId: {}".format(sessionId)) 
        send_message(resp)
        return spb.FAILURE

    # parse request
    if SESSIONS[msg.sessionId]['completed_challenge'] == False or 'client_token' not in SESSIONS[msg.sessionId]:
        resp.status = spb.FAILURE
        resp.encMsg = b''
        resp.encMsgTag = b''
        logging.info("ERROR: challenge not completed for this session")
        send_message(resp)
        return spb.FAILURE

    token = SESSIONS[msg.sessionId]['client_token']
    role = bytes_to_long(token.split(b'|')[1])
    
    (aes_gcm_key, nonce) = HKDF(token, 16, '', SHA512, num_keys=2) 

    if role == spb.ADMIN:
        plain = b'Congratulations - here is your flag: ' + flag
    else:
        plain = b'Welcome USER!'

    a = AES.new(aes_gcm_key, AES.MODE_GCM, nonce = nonce)
    (cipher, tag) = a.encrypt_and_digest(plain)

    # send response    

    resp.status = spb.SUCCESS
    resp.encMsg = cipher
    resp.encMsgTag = tag
    logging.info("SUCCESS: message sent") 
    send_message(resp)

    return spb.SUCCESS

def register_user(USERS, name, pubkey, role = spb.USER):
    len_db = len(USERS)
    uid = len_db + 1
    USERS.append( {"name": name, "pubkey": pubkey, "uid":uid, "role": role} )
    logging.debug("users = {}".format(USERS))
    return uid

if __name__ == "__main__":
    
    logging.debug("creating sessions database")
    # create session database
    SESSIONS = {}

    logging.debug("creating admin user")
    # create admin user
    server_ecdh = ECDH(curve=NIST256p)
    server_ecdh.generate_private_key()
    server_public_key = server_ecdh.get_public_key()
    spub = server_public_key.to_string(encoding='compressed')
    
    logging.debug("creating user database")
    # create user database
    USERS = []
    register_user(USERS, b"admin", spub, role = spb.ADMIN)  


    logging.debug("starting message loop")
    while True:
       m  = recv_message()
       if m != None:
           if m.type == spb.MSG_REGISTER_REQUEST:
               handle_register_request(m)
               continue
           elif m.type == spb.MSG_LOGIN_REQUEST:
               ret = handle_login_request(SESSIONS, m)
               continue
           elif m.type == spb.MSG_LOGIN_CHALLENGE:
               ret = handle_login_challenge_request(SESSIONS, USERS, m)
               continue
           elif m.type == spb.MSG_MESSAGE_REQUEST:
               handle_message_request(SESSIONS, m)
               continue
           else:
               logging.error("Unknown message type, exitting...")
               exit(0)

{{< /code >}}

{{< code language="proto" title="server.proto" expand="Show" collapse="Hide" isCollapsed="true" >}}
syntax = "proto2";

package server;

enum MessageType {
	MSG_LOGIN_REQUEST=0;
	MSG_LOGIN_RESPONSE=1;
	MSG_LOGIN_CHALLENGE=2;
	MSG_LOGIN_CHALLENGE_RESPONSE=3;
	MSG_REGISTER_REQUEST=4;
	MSG_REGISTER_RESPONSE=5;
	MSG_MESSAGE_REQUEST=6;
	MSG_MESSAGE_RESPONSE=7;
}

enum Status {
		SUCCESS = 0;
		FAILURE = 1;
	}

enum Role {
		USER = 0;
		ADMIN = 1;
	}

message MessageHeader {
	required uint32 msglen = 1;
	required MessageType type = 2;
}

message RegisterRequest {
	required MessageType type = 1;
	required bytes name = 2;
	required bytes clientPublicKey = 3;
}

message RegisterResponse {
	required MessageType type = 1;
	required uint32 uid = 2;
	required Status status = 3;
}

message LoginRequest {
	required MessageType type = 1;
	required uint32 uid = 2;
}

message LoginResponse {
	required MessageType type = 1;
	required bytes sessionId = 2;
	required bytes challenge = 3;
	required bytes ephemeralServerPublicKey = 4;
	required Status status = 5;
}

message LoginChallenge {
	required MessageType type = 1;
	required bytes sessionId = 2;
	required bytes challengeResponse = 3;
	required bytes ephemeralClientPublicKey = 4;
}

message LoginChallengeResponse {
	required MessageType type = 1;
	required bytes sessionId = 2;
	required Status status = 3; 
}
	
message MessageRequest {
	required MessageType type = 1;
	required bytes sessionId = 3;
}

message MessageResponse {
	required MessageType type = 1;
	required Status status = 2;
	required bytes encMsg = 3;
	required bytes encMsgTag = 4;
}

{{< /code >}}

We also need to run the command in the server file `protoc -I=. --python_out=. ./server.proto`, to generate `server_pb2.py`.

There's a lot of code to go through, but I'll try to explain the relevant parts:
- The server handles registering new users and logging in.
- To register, the client provides a public key, which must be on the NIST256p curve, then the public key is stored alongside their user id (`uid`), name and role.
- To login, there are two steps.
    - Firstly, the server generates a random challenge and public key, and sends it to us. 
    - Then we must sign the challenge with our public key and send the signature to the server, which checks if the signature is valid. If so, the server calculates the shared secret with its private key and our public key. The server then stores our info (shared secret, role, uid, session id) in a `token`, and sends us our session id.
- We can also request a message, providing a session id. The server retrieves the token corresponding to our session, and checks if we have the admin role. If we do, we get the flag.

I don't think there's anything wrong with the procedures described above, but I noticed our info was being stored in the token in a very bad way:

```py
def handle_login_challenge_request(SESSION, USERS, msg):
    ...
    token  = shared_secret 
    token += b'|' + long_to_bytes(clientRole) 
    token += b'|' + long_to_bytes(uid) 
    token += b'|' + sessionId
```

The server then uses `|` as a delimeter to seperate our info later on:

```py
def handle_message_request(SESSIONS, msg):
    ...
    token = SESSIONS[msg.sessionId]['client_token']
    role = bytes_to_long(token.split(b'|')[1])
    ...
    if role == spb.ADMIN:
        plain = b'Congratulations - here is your flag: ' + flag
    else:
        plain = b'Welcome USER!'
```

`bytes_to_long(token.split(b'|')[1])` retrieves the role by splitting with `|` and getting the second element. This means if we can inject a `|` character into the token somehow, we could trick it into thinking we have the admin role. However, it seems like we can't control any info in the token, which are `shared_secret`, `clientRole`, `uid` and `sessionId`.

But it turns out, the admin role `spb.ADMIN` is actually just the number `1`, and since `shared_secret` is essentially random bytes, there is a chance that it could contain the `|` character.

This is what `token` usually looks like:

```
shared_secret   |role| uid| session id
...\xc3\x87\xf0|\x00|\x02|c8e9fd09-0cb1-4d6c-88d3-53596a98fccb
```

But what if `shared_secret` happened to end with `|\x01`?

```
shared_secret   |role| uid| session id
...\xc3\x87|\x01|\x00|\x02|c8e9fd09-0cb1-4d6c-88d3-53596a98fccb
```

Now the second element when splitting by `|` is `\x01`, the admin role!

Since `shared_secret` is basically random bytes, there is a 1 in $256^2$ which is 1 in 65536 chance that it ends with `|\x01` in which the server thinks we're admin, giving us the flag. This actually meant if you ran the client script, unmodified, enough times, you would get the flag. So I did pretty much that, with slight optimizations.

65536 is not a lot, but probably not a good idea connecting to the server that many times. Luckily, we can create users and login multiple times over the same connection, so we didn't have to open many connections.

```py
while True:
    s = remote(host, port)
    e = create_user()
    uid = register(s,e)
    for i in tqdm(range(0, 1000)):
        (sessionId, chal, sepk) = login(s, uid)
        ceph = login2(s, e, sessionId, chal)

        # calculate shared secret
        server_ephemeral_public_key = VerifyingKey.from_string(sepk, NIST256p)
        ceph.load_received_public_key(server_ephemeral_public_key)
        shared_secret = ceph.generate_sharedsecret_bytes()

        # if shared secret ends with |\x01 , request for the flag
        # (we aren't explicitly checking for |\x01 because there is a chance
        # it could end with |\x00\x01 etc., which is still valid, slightly increasing
        # our chances)
        token  = shared_secret
        token += b'|' + long_to_bytes(spb.USER)
        role = bytes_to_long(token.split(b'|')[1])
        if role == spb.ADMIN:
            msg = request_msg(s, sessionId, uid, ceph, sepk)
            print(f"Got the flag: {msg = }")
            exit()
        else:
            continue

    s.close()
```

After ~30 minutes and running multiple instances, we actually got the flag: `cybears{Wh1ch_pr0gr4m_d0_j3d1_us3_t0_op3n_PDF_f1l35?Ad0b3_W4n_K3n0b1!}`

{{< image src="./img/got_the_fricking_flag.png" alt="" position="center" style="border-radius: 5px; width: 70%" >}}

Full solve script:
{{< code language="python" title="remote_brute.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
'''

python3 client.py -r arpeeceethree.chal.cybears.io:2323



'''

from pwn import * 
from google.protobuf.internal.encoder import _VarintEncoder
from google.protobuf.internal.decoder import _DecodeVarint
import server_pb2 as spb
from google.protobuf.internal.decoder import _DecodeError
import sys 
import argparse

import Crypto.Cipher.AES as AES
import Crypto.Hash.SHA512 as SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes, bytes_to_long

from ecdsa import ECDH, NIST256p, VerifyingKey



def send_message(s, msg):
    """ Send a message, prefixed with its size, to a TPC/IP socket """
    data = msg.SerializeToString()
    mh = spb.MessageHeader()
    mh.msglen = len(data)
    mh.type = msg.type
    s.send(mh.SerializeToString() + data)
    return 

def msg_type(msgtype):
    if msgtype == spb.MSG_LOGIN_REQUEST:
        return spb.LoginRequest()
    elif msgtype == spb.MSG_LOGIN_RESPONSE:
        return spb.LoginResponse()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE:
        return spb.LoginChallenge()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE_RESPONSE:
        return spb.LoginChallengeResponse()
    elif msgtype == spb.MSG_REGISTER_REQUEST:
        return spb.RegisterRequest()
    elif msgtype == spb.MSG_REGISTER_RESPONSE:
        return spb.RegisterResponse()
    elif msgtype == spb.MSG_MESSAGE_REQUEST:
        return spb.MessageRequest()
    elif msgtype == spb.MSG_MESSAGE_RESPONSE:
        return spb.MessageResponse()
    else:
        return None


def check_fields(msg):
    result = True
    for field in msg.DESCRIPTOR.fields_by_name.keys():
        if msg.DESCRIPTOR.fields_by_name[field].label == msg.DESCRIPTOR.fields_by_name[field].LABEL_REQUIRED:
            result &= msg.HasField(field)
    return result

def recv_message(s):
    """ Receive a message, prefixed with its size and type, from stdin """
    # Receive the size of the message data
    # expect [MessageHeader][Message of type]
    data = b''
    header = spb.MessageHeader()
    while True:
        data+= s.recv(1)
        try:
            header.ParseFromString(data)
            if check_fields(header):
                break
        except _DecodeError as e:
            pass

    # Receive the message data
    data = s.recv(header.msglen)

    # Decode the message and validate all required fields are present
    msg = msg_type(header.type)
    if msg != None:
        try:
            msg.ParseFromString(data)
            if not check_fields(msg):
                return None
            return msg
        except _DecodeError:
            return None
    else:
        return None

def create_user():
    client_ecdh = ECDH(curve=NIST256p)
    client_ecdh.generate_private_key()
    return client_ecdh

def register(s, ecdh, name=b'bumblebear', pubkey=b''):
    ## REGISTER
    rr = spb.RegisterRequest()
    rr.type = spb.MSG_REGISTER_REQUEST
    rr.name = name
    if pubkey == b'':
        rr.clientPublicKey = ecdh.get_public_key().to_string(encoding='compressed')
    else:
        rr.clientPublicKey = pubkey

    send_message(s, rr)

    ## REGISTER RESPONSE
    reg_resp = recv_message(s)
    if reg_resp != None:
        pass
        # log.info("DEBUG: received {}".format(reg_resp))
    if reg_resp.status == spb.FAILURE:
        log.error("failed to register")
    uid = reg_resp.uid
    return uid

def login(s, uid):
    ## LOGIN
    l = spb.LoginRequest()
    l.type = spb.MSG_LOGIN_REQUEST
    l.uid = uid
    send_message(s, l)

    ## LOGIN RESPONSE
    login_resp = recv_message(s)
    if login_resp != None:
        pass
        # log.info("DEBUG: received {}".format(login_resp))
    
    return login_resp.sessionId, login_resp.challenge, login_resp.ephemeralServerPublicKey


def login2(s, ecdh, sessionId, challenge):
    ## SIGN CHALLENGE
    sig = ecdh.private_key.sign_deterministic(challenge)

    ## GENERATE EPHEMERAL DH SESSION KEY
    client_ephemeral_ecdh = ECDH(curve=NIST256p)
    client_ephemeral_ecdh.generate_private_key()
    client_ephemeral_public_key = client_ephemeral_ecdh.get_public_key()

    send_chal = spb.LoginChallenge()
    send_chal.type = spb.MSG_LOGIN_CHALLENGE
    send_chal.sessionId = sessionId
    send_chal.ephemeralClientPublicKey = client_ephemeral_public_key.to_string(encoding='compressed')

    send_chal.challengeResponse = sig
    send_message(s, send_chal)

    msg_resp = recv_message(s)
    if msg_resp != None:
        pass
        # log.info("DEBUG: received {}".format(msg_resp))

    return client_ephemeral_ecdh

def request_msg(s, sessionId, uid, client_ephemeral, server_ephemeral):
    ## REQUEST MESSAGE
    # log.info("sending message request")
    msg_req = spb.MessageRequest()
    msg_req.type = spb.MSG_MESSAGE_REQUEST
    msg_req.sessionId = sessionId

    send_message(s, msg_req)

    # log.info("receiving message")
    msg_resp = recv_message(s)
    if msg_resp != None:
        pass
        # log.info("DEBUG: received {}".format(msg_resp))

    ## DECRYPT MESSAGE
    server_ephemeral_public_key = VerifyingKey.from_string(server_ephemeral, NIST256p)

    client_ephemeral.load_received_public_key(server_ephemeral_public_key)
    shared_secret = client_ephemeral.generate_sharedsecret_bytes()

    token  = shared_secret
    token += b'|' + long_to_bytes(spb.USER)
    token += b'|' + long_to_bytes(uid)
    token += b'|' + sessionId
    (aes_gcm_key, nonce) = HKDF(token, 16, '', SHA512, num_keys=2)

    a = AES.new(aes_gcm_key, AES.MODE_GCM, nonce = nonce)
    message = a.decrypt_and_verify(msg_resp.encMsg, msg_resp.encMsgTag)

    # log.info("message received: {}".format(message))
    return message

from tqdm import tqdm

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--remote', help="The address:port of the remote server hosting the challenge", required=True)
    args = parser.parse_args()

    if args.remote != None:
        host = args.remote.split(":")[0]
        port = int(args.remote.split(":")[1])
    else:
        exit(0)

    logging.root.setLevel(logging.ERROR)

    while True:
        s = remote(host, port)
        e = create_user()
        uid = register(s,e)
        for i in tqdm(range(0, 1000)):
            (sessionId, chal, sepk) = login(s, uid)
            ceph = login2(s, e, sessionId, chal)

            # calculate shared secret
            server_ephemeral_public_key = VerifyingKey.from_string(sepk, NIST256p)
            ceph.load_received_public_key(server_ephemeral_public_key)
            shared_secret = ceph.generate_sharedsecret_bytes()

            # if shared secret ends with |\x01 , request for the flag
            # (we aren't explicitly checking for |\x01 because there is a chance
            # it could end with |\x00\x01 etc., which is still valid, slightly increasing
            # our chances)
            token  = shared_secret
            token += b'|' + long_to_bytes(spb.USER)
            role = bytes_to_long(token.split(b'|')[1])
            if role == spb.ADMIN:
                msg = request_msg(s, sessionId, uid, ceph, sepk)
                print(f"Got the flag: {msg = }")
                exit()
            else:
                continue

        s.close()


{{< /code >}}


### A better solution

Even though it worked, I thought that brute forcing on remote was probably unintended, and there should've been some way to brute force locally, but I couldn't see how. Turns out my reading comprehension failed me again - I thought that the server uses the our public key we provided when registering to calculate the shared secret, but actually we provide it with another, ephemeral public key for the session when logging in.

Since the server provides us with its ephermeral public key alongside the challenge, we can generate private keys and calculate the shared secret locally. If the shared secret ends with `|\x01`, we use that public key and send it to the server, which should compute the same shared secret, and give us the flag. This way, we don't need to brute force remote and can get the flag quickly in just one attempt.

Better solve script:

{{< code language="python" title="code.py" expand="Show" collapse="Hide" isCollapsed="true" >}}
'''

python3 client.py -r arpeeceethree.chal.cybears.io:2323



'''

from pwn import * 
from google.protobuf.internal.encoder import _VarintEncoder
from google.protobuf.internal.decoder import _DecodeVarint
import server_pb2 as spb
from google.protobuf.internal.decoder import _DecodeError
import sys 
import argparse

import Crypto.Cipher.AES as AES
import Crypto.Hash.SHA512 as SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes, bytes_to_long

from ecdsa import ECDH, NIST256p, VerifyingKey



def send_message(s, msg):
    """ Send a message, prefixed with its size, to a TPC/IP socket """
    data = msg.SerializeToString()
    mh = spb.MessageHeader()
    mh.msglen = len(data)
    mh.type = msg.type
    s.send(mh.SerializeToString() + data)
    return 

def msg_type(msgtype):
    if msgtype == spb.MSG_LOGIN_REQUEST:
        return spb.LoginRequest()
    elif msgtype == spb.MSG_LOGIN_RESPONSE:
        return spb.LoginResponse()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE:
        return spb.LoginChallenge()
    elif msgtype == spb.MSG_LOGIN_CHALLENGE_RESPONSE:
        return spb.LoginChallengeResponse()
    elif msgtype == spb.MSG_REGISTER_REQUEST:
        return spb.RegisterRequest()
    elif msgtype == spb.MSG_REGISTER_RESPONSE:
        return spb.RegisterResponse()
    elif msgtype == spb.MSG_MESSAGE_REQUEST:
        return spb.MessageRequest()
    elif msgtype == spb.MSG_MESSAGE_RESPONSE:
        return spb.MessageResponse()
    else:
        return None


def check_fields(msg):
    result = True
    for field in msg.DESCRIPTOR.fields_by_name.keys():
        if msg.DESCRIPTOR.fields_by_name[field].label == msg.DESCRIPTOR.fields_by_name[field].LABEL_REQUIRED:
            result &= msg.HasField(field)
    return result

def recv_message(s):
    """ Receive a message, prefixed with its size and type, from stdin """
    # Receive the size of the message data
    # expect [MessageHeader][Message of type]
    data = b''
    header = spb.MessageHeader()
    while True:
        data+= s.recv(1)
        try:
            header.ParseFromString(data)
            if check_fields(header):
                break
        except _DecodeError as e:
            pass

    # Receive the message data
    data = s.recv(header.msglen)

    # Decode the message and validate all required fields are present
    msg = msg_type(header.type)
    if msg != None:
        try:
            msg.ParseFromString(data)
            if not check_fields(msg):
                return None
            return msg
        except _DecodeError:
            return None
    else:
        return None

def create_user():
    client_ecdh = ECDH(curve=NIST256p)
    client_ecdh.generate_private_key()
    return client_ecdh

def register(s, ecdh, name=b'bumblebear', pubkey=b''):
    ## REGISTER
    rr = spb.RegisterRequest()
    rr.type = spb.MSG_REGISTER_REQUEST
    rr.name = name
    if pubkey == b'':
        rr.clientPublicKey = ecdh.get_public_key().to_string(encoding='compressed')
    else:
        rr.clientPublicKey = pubkey

    send_message(s, rr)

    ## REGISTER RESPONSE
    reg_resp = recv_message(s)
    if reg_resp != None:
        pass
        # log.info("DEBUG: received {}".format(reg_resp))
    if reg_resp.status == spb.FAILURE:
        log.error("failed to register")
    uid = reg_resp.uid
    return uid

def login(s, uid):
    ## LOGIN
    l = spb.LoginRequest()
    l.type = spb.MSG_LOGIN_REQUEST
    l.uid = uid
    send_message(s, l)

    ## LOGIN RESPONSE
    login_resp = recv_message(s)
    if login_resp != None:
        pass
        # log.info("DEBUG: received {}".format(login_resp))
    
    return login_resp.sessionId, login_resp.challenge, login_resp.ephemeralServerPublicKey


def login2(s, ecdh, ephemeral_ecdh, sessionId, challenge):
    ## SIGN CHALLENGE
    sig = ecdh.private_key.sign_deterministic(challenge)

    ## GENERATE EPHEMERAL DH SESSION KEY
    client_ephemeral_ecdh = ephemeral_ecdh
    client_ephemeral_public_key = client_ephemeral_ecdh.get_public_key()

    send_chal = spb.LoginChallenge()
    send_chal.type = spb.MSG_LOGIN_CHALLENGE
    send_chal.sessionId = sessionId
    send_chal.ephemeralClientPublicKey = client_ephemeral_public_key.to_string(encoding='compressed')

    send_chal.challengeResponse = sig
    send_message(s, send_chal)

    msg_resp = recv_message(s)
    if msg_resp != None:
        pass
        # log.info("DEBUG: received {}".format(msg_resp))

    return client_ephemeral_ecdh

def request_msg(s, sessionId, uid, client_ephemeral, server_ephemeral):
    ## REQUEST MESSAGE
    # log.info("sending message request")
    msg_req = spb.MessageRequest()
    msg_req.type = spb.MSG_MESSAGE_REQUEST
    msg_req.sessionId = sessionId

    send_message(s, msg_req)

    # log.info("receiving message")
    msg_resp = recv_message(s)
    if msg_resp != None:
        pass
        # log.info("DEBUG: received {}".format(msg_resp))

    ## DECRYPT MESSAGE
    server_ephemeral_public_key = VerifyingKey.from_string(server_ephemeral, NIST256p)

    client_ephemeral.load_received_public_key(server_ephemeral_public_key)
    shared_secret = client_ephemeral.generate_sharedsecret_bytes()

    token  = shared_secret
    token += b'|' + long_to_bytes(spb.USER)
    token += b'|' + long_to_bytes(uid)
    token += b'|' + sessionId
    (aes_gcm_key, nonce) = HKDF(token, 16, '', SHA512, num_keys=2)

    a = AES.new(aes_gcm_key, AES.MODE_GCM, nonce = nonce)
    message = a.decrypt_and_verify(msg_resp.encMsg, msg_resp.encMsgTag)

    # log.info("message received: {}".format(message))
    return message

from tqdm import tqdm

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--remote', help="The address:port of the remote server hosting the challenge", required=True)
    args = parser.parse_args()

    if args.remote != None:
        host = args.remote.split(":")[0]
        port = int(args.remote.split(":")[1])
    else:
        exit(0)

    logging.root.setLevel(logging.ERROR)

    s = remote(host, port)

    # register
    e = create_user()
    uid = register(s,e)

    # login step 1
    (sessionId, chal, sepk) = login(s, uid)
    server_ephemeral_ecdh_pubkey = VerifyingKey.from_string(sepk, NIST256p)

    # generate private keys until shared secret is what we want
    while True:
        client_ephemeral_ecdh = ECDH(curve=NIST256p)
        client_ephemeral_ecdh.generate_private_key()
        
        # calculate shared secret
        client_ephemeral_ecdh.load_received_public_key(server_ephemeral_ecdh_pubkey)
        shared_secret = client_ephemeral_ecdh.generate_sharedsecret_bytes()
        
        token = shared_secret
        token += b'|' + long_to_bytes(spb.USER)
        role = bytes_to_long(token.split(b'|')[1])
        if role == spb.ADMIN:
            break

    login2(s, e, client_ephemeral_ecdh, sessionId, chal)
    
    msg = request_msg(s, sessionId, uid, client_ephemeral_ecdh, sepk)
    print(f"Got the flag: {msg = }")



{{< /code >}}


# Conclusion

BSides Canberra 2024 was again, a great conference, and [Cybears](https://x.com/cybearsctf) hosted another fun CTF! I believe it's truely one of the best conferences out there, and I'll definitely be coming back next year!

I was able to attend thanks to the [Assistance Program](https://www.bsidesau.com.au/assistance.html), which covered my flights and hotel, so special thanks to Kylie, Silvio and Danielle for making this possible!

For coming 2nd place, we won \$500, and a Dungeons and Dragons lego set! We, alongside the other winning teams, skateboarding dogs and French Roomba, all decided to donate our prize money to the Assistance Program, and we hope this helps other people attend the conference in the future! We're keeping the lego set though :P

Btw, if you spotted any errors/typos in the blog, or have questions, feel free to DM/ping me on discord `thesavageteddy`.

Thanks for reading!

- teddy / TheSavageTeddy

{{< image src="./img/conference.jpg" alt="" position="center" style="border-radius: 5px; width: 100%" >}}








