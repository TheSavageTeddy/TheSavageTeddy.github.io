+++
weight = 100
tags = ["ctf", "beginner", "writeup"]
categories = ["CTF Writeups"]
publishDate = 1677600000 # 01/03/2023
description = "Full writeups of all challenges for the qualifier round of a beginner CTF." 
title_img = """{{< image src="https://ctftime.org/media/events/1_1_light_with_text_1.png" alt="" style="border-radius: 5px; height: auto; width: 10vh; display: inline; vertical-align: middle; " >}}"""
title = """Full Writeups - Hack A Bit CTF Qualifiers 0x01"""
cover = """webhook.png"""
cover_alt = ""
+++

# Overview

Hack A Bit is a CTF targeting highschool students aged 13-18. This post will include writeups for all challenges (except OSINT) for Round 2, which was the CTF jeopardy round.

Also, please contact me discord `TheSavageTeddy#7458` if there are any mistakes/issues with these writeups, or if you want more info on them. Enjoy!


# Challenge Categories

[`Welcome`](#0-welcome) - 4 challenges

[`Cryptography`](#1-cryptography) - 8 challenges

[`Web`](#2-web) - 6 challenges

[`Programming`](#3-programming) - 8 challenges

[`Infrastructure`](#4-infrastructure) - 8 challenges

[`Networking`](#5-networking) - 6 challenges

[`OSINT`](#6-osint) - 8 challenges


# 0. Welcome
## Wakeup (5)
> Throughout the course you will prove your completion of tasks and understanding by capturing flags. CTF stands for capture the flag. Flags will generally be formatted as flag{x} where the x is the specific content that will change from challenge to challenge. If this isn't the case, the challenge will specifically state that it uses a non-standard flag format. 

> Submit the flag `flag{hello_world}` to complete this challenge.

Sanity check challenge, flag was in the description.
`flag{hello_world}`

## Weirdo (5)
> This is what a challenge with a non-standard flag will look like. These types of flags are generally used for things like IP addresses or other data that would be a "short answer" style. The challenge will always be marked with a "NON-STANDARD FLAG FORMAT" identifier if it is this way.

> Submit the flag 192.168.1.1/24 to get credit for this challenge.

Same thing, flag is `192.168.1.1/24`. This just tells us some challenges are not in the normal `flag{}` format.

## Support (5)
> Throughout the competition you may want to ask for help. Where can you do that? How can staff members ensure that all information is moderated and everyone receives the same level of support? The answer is that Hack a Bit uses a support forum in discord.

> Navigate to the support form in the competition group and find the thread for this challenge.

> www.discord.gg/hack-a-bit

Joining the discord and navigating to the challenge support posts we find this `flag{helpHelpHELP_desk}`

## Billboard (5)
> What do you get for winning the competition? Where do you look for details on this round and future rounds of the 0x01 season? Check out the HaB website's competition page for more information, there's something there for you.

Going to [https://www.hackabit.com/competition](https://www.hackabit.com/competition) we find `flag{you_might_need_this_for_later}` below the prizes.



# 1. Cryptography


## Homerun (75)
> Check out 0xFF in the ASCII lookup table...  
> Oh dang, it isn't there. Well I still need to send you that data, not the text but the actual value 0xFF in computer memory.
> Here's an example, decode this, all the data you need is right here: `MZWGCZ33I5XXI5DBJVQWWZKTOVZGKWLPOVEGKYLSIFRG65LUKRUGC5CMN5XGOQTBNRWH2===`

We get a ciphertext `MZWGCZ33I5XXI5DBJVQWWZKTOVZGKWLPOVEGKYLSIFRG65LUKRUGC5CMN5XGOQTBNRWH2===`. This is clearly base32 as we see it consists of only uppercase letters and numbers, ending with `=` (padding). Decoding in CyberChef or any other tool gives `flag{GottaMakeSureYouHearAboutThatLongBall}`

## Mason (75)

> The numbers mason, what do they mean?
> ```66 6c 61 67 7b 63 6f 6d 70 75 74 65 72 3a 69 5f 6f 6e 6c 79 5f 75 6e 64 65 72 73 74 61 6e 64 5f 62 69 6e 61 72 79 5f 64 75 64 65 7d```

Ciphertext consists of 0-9 and a-f, hinting that it's hex. Decoding from hex gives `flag{computer:i_only_understand_binary_dude}`

## Smiley (100)

> Existing encryption is dumb, so I came up with something better. Maybe its a little emotional or whatever, but I feel like you can get through that part...

> Breaking this teaches you some of the primative concepts professionals use to attack novel cryptographic algorithms. It also demonstrates in a primative way why we use established and tested ones for real applications. It also loosely relates to a concept called "known plaintext."

> *In the prompt, there is no punctuation and everything is lowercase alphabetical characters.*

Given a file containing this:
```
🤣😅😇😉 😁😅😀🥰🤣 😚🥰😜🤗😇🤑🤫😉 😀 🫡😇😉🤣 😜🤐 🤣😅🤫 😶😮‍💨😇😁😜🤑🤫 🤫🤥😜🤤😇 😁😅😀🥰😀😁🤣🤫🥰😉 😀😮‍💨🤑 😉🤫🤕😶🤫😮‍💨😁🤫😉 🤮😇🤣😅 😇🤥😀🥶🤫😉 🤐🥰😜🤥 🤑😇🤐🤐🤫🥰🤫😮‍💨🤣 🤗🤫😮‍💨🤑😜🥰😉 😁🫡🤑🥰 😮‍💨😀🤥🤫 🤑😀🤣🤫 😉😜😶🥰😁🤫 😀😮‍💨🤑 🤯🤫🥳🤮😜🥰🤑😉 🤐🫡😀🥶🥸😉🤥😇🫡🤫😎🤥😜🥰🤫😎😉🤥😇🫡🤫😎🤠😇🥶🥶🤫🥰🧐
```

This challenge was a bit annoying. It was clearly frequency analysis, which is like using the fact that letters `e`, `a` etc are more common than `q` or `z`.

First I mapped each emoji to a unique character or number using this (uncleaned) code:

```py
emoji_text = "🤣😅😇😉 😁😅😀🥰🤣 😚🥰😜🤗😇🤑🤫😉 😀 🫡😇😉🤣 😜🤐 🤣😅🤫 😶😮‍💨😇😁😜🤑🤫 🤫🤥😜🤤😇 😁😅😀🥰😀😁🤣🤫🥰😉 😀😮‍💨🤑 😉🤫🤕😶🤫😮‍💨😁🤫😉 🤮😇🤣😅 😇🤥😀🥶🤫😉 🤐🥰😜🤥 🤑😇🤐🤐🤫🥰🤫😮‍💨🤣 🤗🤫😮‍💨🤑😜🥰😉 😁🫡🤑🥰 😮‍💨😀🤥🤫 🤑😀🤣🤫 😉😜😶🥰😁🤫 😀😮‍💨🤑 🤯🤫🥳🤮😜🥰🤑😉 🤐🫡😀🥶🥸😉🤥😇🫡🤫😎🤥😜🥰🤫😎😉🤥😇🫡🤫😎🤠😇🥶🥶🤫🥰🧐"
from string import ascii_lowercase
cs = ascii_lowercase + "1234567890"

mapping = {}
nextind = 0
txt = ""
for thing in emoji_text:
    if thing == " ":txt += " ";continue
    if thing not in mapping.keys():
        mapping[thing] = cs[nextind]
        txt += mapping[thing]
        nextind+=1
    else:
        txt += mapping[thing]
    
print(txt)
```

This gave us `abcd ebfga hgijckld f mcda in abl opqrceikl lsitc ebfgfealgd fpqrk dluolpqreld vcab csfwld ngis kcnnlglpqra jlpqrkigd emkg pqrfsl kfal diogel fpqrk xlyvigkd nmfwzdscml1sigl1dscml12cwwlg3` to work with, which is much more readable.

Then I used [quipquip](https://quipqiup.com/), a cryptogram solver. 

{{< image src="./img/quipquip.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

This gives us the flag `flag{smilemoresmilebigger}`, or something like that.

## Matchmaker (100)

> There are a variety of symmetric cryptosystems out there, but most of them involve a logic block called a XOR. The key is "hab"(UTF8). We're giving you the key and the algorithm, how hard can it be?

> `Dg0DDxoRBz4PHQIKNxIbBQwHHBMbFQ==`

We are given base64, and the XOR key "hab". Using CyberChef we can decrypt and XOR to get the flag. `flag{so_much_symmetry}`

{{< image src="./img/matchmaker1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

# Hancock (125)

> I stole this session token from someone and it looks like all I need to do is change admin to true for all the power... no idea who signed it though... can you figure out the secret for me so that we can get some pwnage going?

> The secret for this token is somewhere in the RockYou wordlist https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

We are given this string

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxMjM0NTY3ODkwLCJhZG1pbiI6ZmFsc2V9.QR_da_OHe58LBwBRt5S_aTcbMkBhEFqJkFn7zUq7Yyc
```

which is clearly a JWT (Json Web Token).

These are commonly issued as a cookie to authenticate a user, such as for a session. We can verify this by going to [https://jwt.io/](https://jwt.io/).

The flag is the secret that was used to sign the JWT.

{{< image src="./img/jwt.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Looking up a tool to brute force secrets for the JWT, we find [jwt-pwn](https://github.com/mazen160/jwt-pwn).

Using this, we brute force possible secrets with the [rockyou.txt wordlist](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt), and get the flag `ghosthunter`

{{< image src="./img/jwtcrack.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Trending (125)

> All the existing hashing algorithms are dumb, why give me a fixed length? If I give you more input you should give me even more output, its only fair! I wrote a new hashing algorithm that improves on the best of the best (MD5)! Check it out and see if you can break it (you probably can't)!

> Here's your hash: `b18f21b19e0f86b22d218c86e182214b867b36212576b2617e8c03862d369e`

We are given a python file with a custom 'hashing' algorithm.

```py
#!/usr/bin/python3

import sys
import hashlib
import random
import string

try:
    # get a five character string to use for randomness (lol)
    one_time_pad_or_something = ''.join(random.choices(string.digits, k=5))
    print(one_time_pad_or_something)
    
    # itterate over each character in the input
    for index,character in enumerate(sys.argv[1]):

        # get md5 hash of (that character plus minus pad)
        calculated_character = chr(ord(character) - int(one_time_pad_or_something[index % 5]))
        full_md5_hash = hashlib.md5(calculated_character.encode('ascii'))

        # take the first four characters and print them to the screen
        print(full_md5_hash.hexdigest()[0:2], end="")
    
    # new line at end of output
    print()

# verify that we got input in position
except IndexError: sys.exit("Usage: python3 hashbrown.py <plaintext>")

```

The OTP (one-time pad) is made of 5 digits, so there are `10^5 = 10000` permutations it can be, which is definitely brute force-able.

Now lets look at the code. It loops over each character of our input (the flag), sets `calculated_character` to the flag character, minus a number in the OTP. Then it hashes the character, and outputs the first byte of the hash.

```py
calculated_character = chr(ord(character) - int(one_time_pad_or_something[index % 5]))
full_md5_hash = hashlib.md5(calculated_character.encode('ascii'))
print(full_md5_hash.hexdigest()[0:2], end="")
```

This is repeated for every character in the flag.

Our procedure to recover the flag becomes clear - brute force every OTP, and hash every character the flag could be to recover each flag character.

```py
import hashlib
import binascii
import string
import itertools

charset = string.ascii_lowercase + "{}" + "_"
padcharset = string.digits

ct = 'b18f21b19e0f86b22d218c86e182214b867b36212576b2617e8c03862d369e'

for a in itertools.product("0123456789", repeat=5):
    otp = "".join(a)

    flag=''
    for i in range(len(ct)//2):
        portion = ct[i*2:i*2+2]
        for thing in charset:
            calculated_character = chr(ord(thing) - int(otp[i % 5]))
            full_md5_hash = hashlib.md5(calculated_character.encode('ascii'))
            if full_md5_hash.hexdigest()[0:2]==portion:
                flag+=thing
                break

    if 'flag' in flag:
        print(flag, otp)
```

And we get the flag `flag{dont_roll_your_own_crypto}`

{{< image src="./img/hashbrown.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Powerhouse (150)

> NON-STANDARD FLAG FORMAT

> Here is an RSA key, sort of; provide p and q as `p;q`, like if p was 11 an q was 7, the flag would be `11;7`.

> N = `6176128969` e = `1187`

We get a (very unsecure) RSA public key consisting of `N` (public modulus) and `e` (public exponent).

But we don't need to worry about any of that. In RSA, `N = p * q` where `p` and `q` are 2 primes. Therefore, we just factor `N` to get the flag using [factordb](http://factordb.com/), or any other factoring method (N is very small).

Flag `11329;545161`

# Banker (150)

> NON-STANDARD FLAG FORMAT

> Crack this pin code. It's between 4-8 characters and all numeric.
> `320f5cef77246cdce15f9b66e9e4f3ad22f506f9cd28d85e7ccc8839b301e736`

This challenge doesn't give a lot of info. The ciphertext looks like hex, but we get garbage when we try to decode it. However, notice the hex string is 64 bytes long, which is the size for some hashes.

Putting the hex into [crackstation](https://crackstation.net/), to look up the hash, we find it is the `sha256` hash of `05593620` and we get the flag.


# 2. Web

## Detective (75)
> Visit the webapp and take a look around, detective: https://erpvlnzxrh.qualifier.hackabit.com/detective

Viewing the page source we find `flag{animated` in the HTML. Going to sources and looking the javascript file we find `_commentary_on_`, and going to css we find `css}`.

This gets us the flag `flag{animated_commentary_on_css}`

## Spectator
> Now how about this one? Maybe just look a little harder... https://erpvlnzxrh.qualifier.hackabit.com/spectator

Going to sources we find `flag{there_are_soooooo` in the javascript file (this is also in local storage).

```js
window.onload = function(){  
    window.localStorage.setItem("flag_stuff", "flag{there_are_soooooo")    
}
```

Going to cookies we find `flag_stuff` set to `_many_ways_to`.

Curling the site with extra info (`-v`) using `curl -v https://erpvlnzxrh.qualifier.hackabit.com/spectator` we get `more_flag_stuff: _manage_data}` in the headers, giving us the flag `flag{there_are_soooooo_many_ways_to_manage_data}`

## Nevermind (100)

> If you take something, you gotta put it back, or something at least: https://erpvlnzxrh.qualifier.hackabit.com/nevermind

We are presented with a webpage with a image and text saying:

```
Download this beautiful image and get the MD5 hash of it. Then decide its not that beautiful and POST it back to the same page with header "md5_image_hash" set to that value.
```

So we download the image, md5 hash it and get `021d99868f8b0943b2cf04e944ddab8f` which we post back to the server with the right header using `curl -X POST --header "md5_image_hash: 021d99868f8b0943b2cf04e944ddab8f" https://erpvlnzxrh.qualifier.hackabit.com/nevermind` and get the flag: `flag{nevermind_not_that_beautiful}`

## Delegate (100)

> When we get code execution by compromising a web application, we generally want to exfiltrate some data. The staff did the hard part and gave you code execution, now just exfil that data! https://erpvlnzxrh.qualifier.hackabit.com/delegate

The site includes 2 fields: Epoch and Destination.

In Epoch we need to put a time, and in destination we can put a URL. After putting the correct epoch (unix time) and a URL, we get the message `yup, nice... sent the flag to: https://<the url we provided>`

So let's generate a [webhook](https://webhook.site/) to see what it does to the URL we provide it.

And indeed, it sends us a flag `flag{whats_good_mr_mailman}`

{{< image src="./img/webhook.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Injector (125)


> Someone didn't listen closely in programming class... yeah it was me I guess, I didn't. Here's a super secure login page, if you can bypass it you might even get a flag...

> https://fsiybpfkid.qualifier.hackabit.com/injector

Injector refers to SQL injection, where unsanitized input can lead to all sorts of security vulnerabilities.

Searching up a [cheatsheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/) we try payload and find this one works `admin' or '1'='1'#`, giving us the flag `flag{maveric_pull_the_lever!}`

Note that this is basically blind SQL injection as we have minimal info about the server.

{{< image src="./img/sql.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Brain (125)

> Only admins can get flags... follow the rules!

> https://fsiybpfkid.qualifier.hackabit.com/brain

This was straightforward, but annoying. The page tells us how to get the flag.

{{< image src="./img/brain.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

There are 4 checks we need to pass to get the flag.

Setting the header is trivial with [burpsuite](https://portswigger.net/burp), we can intercept our GET request and manually set the header.

Let's ignore the second one for now. The third one requires us to set a URL parameter, which we can do so by appending `?give-me-that-flag=hand-it-over` to the URL.

For the final one, we check our cookies to find a session cookie `"bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOiJmYWxzZSJ9.lq4IQYyT1PxeSQ89DB7pu9i3rPEdPDAQtiSKJSk9VVo"`

It's another JWT! We just head to [jwt.io](https://jwt.io) and change `admin` to `true`, and replace the JWT with the forged one `"bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOiJ0cnVlIn0.1zlAeGts8dU1rtt-EB0VcbVwhGA_-UkZIzQQY2u96qs"`. This one doesn't require the JWT to be re-signed.

{{< image src="./img/2outof4.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And this is how you set the header:

{{< image src="./img/headers.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

{{< image src="./img/notyet.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Now we just need to brute force numbers 1-100 for the 2nd check! I just automated this with a simple script like this:

```py
import requests

for i in range(1,101):
    url = f'https://fsiybpfkid.qualifier.hackabit.com/brain?my-int={i}'
    resp = requests.get(url)
    print(resp.text)
    if 'pass-icn' in resp.text: # check if pass icon is in the response
        print(url)
        break
```

And we get 72 as the secret number.

Adding it as another parameter with `&my-int=72` (`&` for multiple URL paramters) in burpsuite we get the flag!

`flag{insaayne_in_da_membrain}`

{{< image src="./img/insane.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}



# 3. Programming

# Blobs (75)

> Hey there navigator, its time to follow some directions. Take your challenge input (file) and start at the initial position, such as the below x=52, y=-31. Just like you are on a 2d graph, move in the direction the arrows tell you to. In the below example you end up in the same x position for a difference of 0 and down one for a y difference of -1. Take your final position, in this case 52, -32 and multiply the values together--that is your final position. The answer to the sample prompt is -1664.

Sample prompt:
```
(52,-31)

↘ ↙ ↘ ↙ ↘ → ← ↖ ← ↗ ↘ ↑ ↑ ↓ ↗ ← → ↙ ↖ ↑
```

Simple programming challenge, but I really couldn't be bothered with 8 if/switch case statements so I just used chatGPT, which generated this script and solved it with some modification. Flag `-2025780`

```py
#CHAT GPT DID IT

# Initial position
x, y = 136,-8891

directions = "(omitted because too long)"

# Iterate through the directions and update the position
for direction in directions:
    if direction == "←":
        x -= 1
    elif direction == "→":
        x += 1
    elif direction == "↑":
        y += 1
    elif direction == "↓":
        y -= 1
    elif direction == "↖":
        x -= 1
        y += 1
    elif direction == "↗":
        x += 1
        y += 1
    elif direction == "↙":
        x -= 1
        y -= 1
    elif direction == "↘":
        x += 1
        y -= 1

# Multiply the final position to get the answer
answer = x * y
print(answer)
```

# Buckets (75)

> Grab the data file and add up all the times danny and elise appear. Multiple those two numbers together, that is your challenge answer.

This is yet another programming challenge, even easier than the previous. Use `.count()` to count how many times each appears. I couldn't be bothered reading the file, but it would've been `data=open('filename','r').read()`

```py
data = "omitted because too long"
a = data.count('danny')
b = data.count('elise')
print(a*b)
```

## Pancakes (100)

> Okay we're doing it again, just giving you the flag... should be easy enough right? Well now lets talk about compiled code. This is the same code compiled for a bunch of different architectures. First, figure out which binary is compatible with your system, then just run it to get the flag!

We are given a zip file with a bunch of binaries! All of them are the same - they are just for different architectures/OS etc. Running any will give the flag. For me, running `./binary_18` on WSL gave the flag `flag{bob_the_architect}`

## Linguist (100)

> Grab this file and check it out. You'll notice that it's Python3! Python is an interpreted language, you can read the code but it'll be easier to just interpret it!

> This challenge is juxtaposed to Pancake, which is compiled code. Once you interpret this code with the Python3 interpreter, try to read it and see if you understand what it's doing as a bonus!

Given python code:

```py
import random
import time

flag = b"\xf9\xf3\xfe\xf8\xe4\xeb\xf7\xf6\xec\xc0\xf6\xec\xf1\xeb\xc0\xec\xef\xfe\xf1\xf6\xec\xf7\xc0\xfd\xea\xeb\xc0\xf6\xc0\xec\xeb\xf6\xf3\xf3\xc0\xf1\xfa\xfa\xfb\xc0\xfe\xf1\xc0\xf6\xf1\xeb\xfa\xed\xef\xed\xfa\xeb\xfa\xed\xe2"

class ANSI:
    COLORS = [ "\033[0;30m", "\033[0;31m", "\033[0;32m", "\033[0;33m", "\033[0;34m", "\033[0;35m",
               "\033[0;36m", "\033[0;37m", "\033[1;30m", "\033[1;31m", "\033[1;32m", "\033[1;33m",
               "\033[1;34m", "\033[1;35m", "\033[1;36m", "\033[1;37m" ]

    STYLES = [ "\033[1m", "\033[2m", "\033[3m", "\033[4m", "\033[5m", "\033[7m", "\033[9m" ]
    
    END = "\033[0m"

if __name__ == '__main__':
    try:
        while True:
            print("",end="\r")
            for i in flag: print(f"{random.choice(ANSI.COLORS)}{chr(i ^ 0x9F)}{ANSI.END}", end="")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("",end="\r")
        for i in flag: print(f"{chr(i ^ 0x9F)}", end="")
        print("  ")
```

No reversing is needed - just running the file gives the flag `flag{this_isnt_spanish_but_i_still_need_an_interpreter}`

## Wrench (125)

> Think of this challenge like a bolt and go build a wrench.

> Here's your blueprint:

> Connect to the server on strfjebijc.qualifier.hackabit.com:54321 and get your challenge input. Add up all the decimal integers and only the decminal integers, no hex numbers or strings count. Send that result back within 3 seconds to get the flag

We are given a bunch of text seperated by newlines when we connect using netcat. The challenge says to add up all decimal numbers, and send the result within 3 seconds. We will use [pwntools](https://docs.pwntools.com/en/stable/) to automate this, and do it within 3 seconds.

```py
from pwn import *
import string

r = remote("strfjebijc.qualifier.hackabit.com", 54321)

things = r.recvuntil(b"total: ", drop=True).decode()
things = things.split("\n")
total = 0
for thing in things:
    if thing.isdigit(): # check its a decimal number
        total+=int(thing)

r.sendline(str(total))
r.interactive()
```

And we get the flag `flag{i_feel_the_need_the_need_for_speed}`

## Bites (125)

> Here's a blob of data. Thats it. Just Data. Not any specific data. Just 1's and 0's...

> Process this file. There are series of bytes from 0x02 to 0xFF. Each of these strings of bytes are surrounded by a null byte (0x00). Finally, there are also byte strings of all 0x01. Your mission is to add up all the bytes in the byte strings that are not 0x01 byte strings. The flag is the integer value of all those bytes added up.

> The "flag" is just the total sum, no flag{}.

We are given a file, and told to add up all the bytes, apart from `0x01`. So we will do just that with python. Note that when looping over a bytes object in python, each element is a number 0-255, which is why it is ` == 1` instead of `== b"\x01"`

```py
from Crypto.Util.number import bytes_to_long

f = open("bites.bin","rb").read()
total=0
for thing in f:
    if thing == 1:
        pass
    else:
        total+=thing

print(total)
```

And we get the flag `512490`

## Speed (150)

> You probably shouldn't do this one by hand... Instead write a sorting algorithm that efficiently organizes this file of numbers smallest to biggest. Your flag is the 52133rd number once sorted, starting from 0. Ie: sorted_numbers[52133].

> On an average computer, an efficient algorithm should be able to solve this in around 10 seconds.

We are given a large file, and told to sort it, and submit the 51233th item (0-indexed) as the flag. So as always, python is sufficient to solve this, getting the flag `1235203980`

{{< image src="./img/sort.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

No need to code your own algorithm - every language has builtin sorting algorithms already. Though sorting algorithms *are* interesting...

Small note: I should have done `map(int, f)` to convert every string in `f` to a number, *then* sort, but this didn't matter in this case as with integers only, alphabetical is same as numerical.

## Abundance (150)

We are given a binary. Decompiling it online at [dogbolt](https://dogbolt.org/) recovers some code:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rbx
  char s[8]; // [rsp+0h] [rbp-C0h] BYREF
  __int64 v6; // [rsp+8h] [rbp-B8h]
  __int64 v7; // [rsp+10h] [rbp-B0h]
  __int64 v8; // [rsp+18h] [rbp-A8h]
  char v9; // [rsp+20h] [rbp-A0h]
  char s1[8]; // [rsp+30h] [rbp-90h] BYREF
  __int64 v11; // [rsp+38h] [rbp-88h]
  __int64 v12; // [rsp+40h] [rbp-80h]
  __int64 v13; // [rsp+48h] [rbp-78h]
  __int64 v14; // [rsp+50h] [rbp-70h]
  __int64 v15; // [rsp+58h] [rbp-68h]
  __int64 v16; // [rsp+60h] [rbp-60h]
  __int64 v17; // [rsp+68h] [rbp-58h]
  __int64 v18; // [rsp+70h] [rbp-50h]
  __int64 v19; // [rsp+78h] [rbp-48h]
  __int64 v20; // [rsp+80h] [rbp-40h]
  __int64 v21; // [rsp+88h] [rbp-38h]
  int v22; // [rsp+90h] [rbp-30h]
  __int64 v23; // [rsp+A0h] [rbp-20h]
  int i; // [rsp+ACh] [rbp-14h]

  v23 = 3735928559LL;
  *(_QWORD *)s1 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0LL;
  v17 = 0LL;
  v18 = 0LL;
  v19 = 0LL;
  v20 = 0LL;
  v21 = 0LL;
  v22 = 0;
  *(_QWORD *)s = 0x90978884989E9399LL;
  v6 = 0xA08C8B9E978BA09ELL;
  v7 = 0x8B8B8B8B8B90939ELL;
  v8 = 0x828C9A8B869DA09ELL;
  v9 = 0;
  for ( i = 0; ; ++i )
  {
    v3 = i;
    if ( v3 >= strlen(s) )
      break;
    s[i] = ~s[i];
  }
  while ( 1 )
  {
    printf("What is the entry point of this binary (like 0x1070)?: ");
    fgets(s1, 150, _bss_start);
    s1[strcspn(s1, "\n")] = 0;
    if ( v23 != 3735928559LL )
    {
      puts(s);
      return 0;
    }
    if ( !strcmp(s1, "0x1100") )
      break;
    puts("That's not right?? :(\n");
  }
  puts("Yeah I guess you got it... but whatever man!");
  return 0;
}
```

We see that `s` seems to be the flag, and it seems to be made of some hex strings in the variables `v6`, `v7`, `v8`. However, each byte of `s` is changed to `~s[i]`, which is bitwise negation/NOT operator.

Since `~~s = s`, we can just bitwise NOT it again and get the flag.

{{< image src="./img/not.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Accounting for endianness by rearranging the string `ohw{galf_staht_atttttola}setyb_a` gives `flag{whoa_thats_alottttta_bytes}`. Didn't need to run the binary to get the flag I guess.

# 4. Infrastructure

## Captain (75)

> Cloud infrastructure is migrating to containerized technology in many places, lets get started with containers. Run this docker container with the environment variable `FLAG_ENABLER` set to `give_me_the_flag`.

> https://hub.docker.com/r/nathanielsinger/hackabit0x01-infrastructure-container1

Initially I tried to pull the image and analyse it, but gave up quickly and realised doing it properly was easier. Use `-e` flag to set enviroment variables.

`sudo docker run -e FLAG_ENABLER=give_me_the_flag nathanielsinger/hackabit0x01-infrastructure-container1`

`flag{you_aren't_the_captain_just_yet}`

{{< image src="./img/docker1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Seashell

> SSH runs the internet. Connect to `utkwrgubhj.qualifier.hackabit.com` on port `22` with user `hackerman` and the provided `private key`.

I did this on MacOS, by importing the key, but here is it again on linux (WSL). Private key file is called `id_rsa`. Note that for the private key file, the permissions cannot be too open, so you have to use `chmod 400 id_rsa`.

Connecting with `ssh -i id_rsa hackerman@utkwrgubhj.qualifier.hackabit.com` we get the flag `flag{shesellsseashellsbytheseaaaaaaashore}`.

{{< image src="./img/ssh.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Loading (100)

> What's in this ISO thing?
> https://hub.docker.com/r/nathanielsinger/hackabit0x01-infrastructure-container1

Ok we are given like no info, let's dump the image with `docker save -o dockerimage.tar nathanielsinger/hackabit0x01-infrastructure-container1`

Then just untar (`tar -xvf FILE.tar`) the entire thing, and search through folders. Eventually in `adb6d`.... I found the flag in `root/flag_image.iso` after untarring `layer.tar` in the folder.

`flag{consider_it_loaded_hackerman}`

{{< image src="./img/docker2.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Location (100)

> Now with the same image, dive on in and find the iso image. What is the absolute path to the iso image stored within the container? Include the filename in the path for your submission.
> https://hub.docker.com/r/nathanielsinger/hackabit0x01-infrastructure-container1

To be honest I forgot what the flag to this was, but it's linked to the previous challenge, and we just specify the path to the `.iso` image. So it would've been something like `root/flag_image.iso` or `/root/flag_image.iso`

## Connector (125)

> Connect to the mysql server at dyxvqmjwaj.qualifier.hackabit.com and read out the flag. Here are some user accounts:
> `user1:uyqhxgxcxd` `user2:ehaigdexhh` `user3:xfgyuvtapt` `user4:tnvgijqxei` `user5:hybplwmndy`

We are given 5 user credentials. On my Mac, using SQL Workbench, I tried each one and checked the tables until I found a flag in one of them (`user4`).

{{< image src="./img/connect.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

{{< image src="./img/sqlflag.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And we get the flag `flag{oh_sql_my_sql}`

## Boat (125)

> Sometimes we need to run a machine on a specific address or virtualize a network, get this running on: `172.22.1.11.`

> https://hub.docker.com/r/nathanielsinger/hackabit0x01-infrastructure-container2

Seems easy enough, just run another docker command. But this time, we get an error when we try to pull the image.

```
Error response from daemon: manifest for nathanielsinger/hackabit0x01-infrastructure-container2:latest not found: manifest unknown: manifest unknown
```

Searching for the error brings us to [this](https://stackoverflow.com/questions/41810104/docker-manifest-unknown-manifest-unknown) stack overflow question, and we see we have to specify the version of the image. So we do so and `docker pull nathanielsinger/hackabit0x01-infrastructure-container2:v1.0.0` works.

Using yet another [article](https://stackoverflow.com/questions/27937185/assign-static-ip-to-docker-container) we use the command `docker network create --subnet=172.22.1.11/16 net1` to make a network and `docker run --net net1 --ip 172.22.1.11 nathanielsinger/hackabit0x01-infrastructure-container2:v1.0.0` to run the container with that network and correct ip.

`flag{its_just_an_address_man}`

{{< image src="./img/docker3.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Inspector (150)

> Oh look its Bits, something changed though... see if you can track it down.

We are provided with a zip file containing source code for what seems to be the Bits bot on the CTF's discord server. After looking around, I realise we are given a git folder which contains `.git` folder, with things like past commits and versions.

So the flag must be somewhere in the past commits.

Searching for `flag` with `grep -r "flag" .` we find past commits with `flag_stuff` in their info.

{{< image src="./img/git1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

So we use `git checkout <flagcommithash>` to switch to that commit, and another grep reveals the flag.

`flag{don't_try_harder...look_harder}`

{{< image src="./img/git2.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## Hammer (150)

> Check out oslyxpzcgs.qualifier.hackabit.com and see if you can find the vuln. No help on this one, nothing crazy though... enumerate harder :)
> The flag is stored in an environment variable.

Let's nmap the domain to find more info about the service.

{{< image src="./img/nmap.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

We find an open port `21` which is TCP, so let's connect using netcat:

{{< image src="./img/vsftp.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

We see it is running `vsFTPd 2.3.4`, and a quick google search reveals that it has a [smiley face backdoor](https://en.wikipedia.org/wiki/Vsftpd).

Now, it is intended that we use Metasploit to automatically solve this, but I did it manually while booting up a linux computer to run Metasploit.

First I found the source code for the Metasploit module [here](https://www.exploit-db.com/exploits/49757).

Essentially, if you include `:)` in your username, a reverse shell will be sent to you at port 6200. So we do so, and connect at port 6200 for a shell.

{{< image src="./img/ftp1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And we check the enviroment variables for the flag. `flag{looks_like_you_found_the_right_nail}`

{{< image src="./img/revshell.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}




# 5. Networking

## Phonebook (75)

> Check out the DNS records for `qualifier.hackabit.com`... there's soemthing interesting there, all kinds of data...

Okay let's go to [dnschecker.org](https://dnschecker.org/all-dns-records-of-domain.php) and check the DNS records.

{{< image src="./img/dns.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Wow! A flag! Who would've guessed... `flag{my_nameserver_is_slimshady}`

## Avenue (75)

> What is the kernel(OS) was this network capture recorded on?

We are given a `pcap` capture file. Let's use wireshark to open it.

{{< image src="./img/wireshark.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And within one of the tls streams we find `X11; Ubuntu; Linux x86_64` to be the OS of the capturing device.

## Rivers (100)

> Follow the river and see whats in the stream.

Okay, so this was also just following the TLS stream, hence the name and description. The flag is in the previous image too, `flag{rivers_run_streams_flowwww}`

## Fish (100)

> What protocol is responsible for the most packets in this capture?

Sorting by protocol, we find the `QUIC` protocol to be most of the packets.

But submitting that doesn't give us the flag. A quick google brings us to its full name, `Quick UDP Internet Connections`, which I don't think was the flag either? It was something like `QUIC IETF` or so.

## School (125)

> This ones gonna take a few steps:

> Take the input line by line
> Calculate the network and broadcast addresses of the subnet
> For each network address add up all the forth octets
> Your challenge response (flag) is this total.

Okay, I literally chucked this challenge into chat GPT to solve it for me, and it actually worked first try!

It gave me this code:

```py
def get_network_address(ip, netmask):
    ip_parts = [int(x) for x in ip.split('.')]
    netmask_parts = [int(x) for x in netmask.split('.')]
    network_address = [ip_parts[i] & netmask_parts[i] for i in range(4)]
    return '.'.join(str(x) for x in network_address)

def get_broadcast_address(ip, netmask):
    ip_parts = [int(x) for x in ip.split('.')]
    netmask_parts = [255 - int(x) for x in netmask.split('.')]
    broadcast_address = [ip_parts[i] | netmask_parts[i] for i in range(4)]
    return '.'.join(str(x) for x in broadcast_address)

def main():
    filename = 'school.txt'
    with open(filename) as f:
        lines = f.readlines()
        sum_of_fourth_octets = 0
        for line in lines:
            ip, mask = line.strip().split('/')
            netmask = '.'.join([str((0xffffffff << (32 - int(mask))) >> i & 0xff) for i in [24, 16, 8, 0]])
            network_address = get_network_address(ip, netmask)
            broadcast_address = get_broadcast_address(ip, netmask)
            print(f'IP: {ip}/{mask}')
            print(f'Network address: {network_address}')
            print(f'Broadcast address: {broadcast_address}')
            sum_of_fourth_octets += int(network_address.split('.')[3])
        print(f'Sum of fourth octets: {sum_of_fourth_octets}')

if __name__ == '__main__':
    main()
```

Which gave us the answer `25604`. I am very surprised this worked, and saved me from doing some scripting. So I do apologise for not doing this properly and explaining how to calculate it, hopefully that code is enough :)

## Picture (125)

> There is a service running on woxuazsgxd.qualifier.hackabit.com:54321

> Connect to it and try to follow the mail...

Connecting to it with netcat gives us a message along the lines of the flag was sent to you to a random UDP port 5000-5500

Definetly one of the harder ones by far. My initial thought was to use Wireshark to capture packages, and filter by protocol UDP or port number, but neither of that worked for some reason. Trying another packet capture method with `sudo tcpdump -i ens3 udp -vvv -X`, we get the flag `flag{the_mailman_is_confused_but_you're_not}`

```
14:49:48.524413 IP (tos 0x40, ttl 55, id 741, offset 0, flags [DF], proto UDP (17), length 72)
    201.15.132.34.bc.googleusercontent.com.1235 > vps-7443235f.vps.ovh.ca.5236: [udp sum ok] UDP, length 44
        0x0000:  4540 0048 02e5 4000 3711 fb0b 2284 0fc9  E@.H..@.7..."...
        0x0010:  8b63 87c4 04d3 1474 0034 d36f 666c 6167  .c.....t.4.oflag
        0x0020:  7b74 6865 5f6d 6169 6c6d 616e 5f69 735f  {the_mailman_is_
        0x0030:  636f 6e66 7573 6564 5f62 7574 5f79 6f75  confused_but_you
        0x0040:  2772 655f 6e6f 747d                      're_not}
```

Still not sure why wireshark didn't work, if anyone has an explanation please let me know!



# 6. OSINT

Okay, I only solved 2 out of 8 OSINT challenges, so I won't be doing any OSINT writeups. I really couldn't be bothered with OSINT after all the other chals, as I don't really enjoy OSINT particularly.

So that's it for the writeups! Doubt anyone read almost 1000 lines of Markdown, but thanks for reading!

- teddy / TheSavageTeddy