+++ 
tags = ["ctf"]
categories = ["CTF Writeups"]
date = "2023-2-24" # FIX CHANGE THIS
description = "Full Writeups for a beginner CTF for students." 
title = "Full Writeups - Hack A Bit 0x01"
+++

# Overview

Hack A Bit is a CTF targeting highschool students aged 13-18. This post will include writeups for all challenges (except OSINT) for Round 2, which was the CTF jeopardy round.

# Challenge Categories


# 0. Welcome
## Wakeup (5)
> Throughout the course you will prove your completion of tasks and understanding by capturing flags. CTF stands for capture the flag. Flags will generally be formatted as flag{x} where the x is the specific content that will change from challenge to challenge. If this isn't the case, the challenge will specifically state that it uses a non-standard flag format. 

> Submit the flag flag{hello_world} to complete this challenge.

Sanity check challenge, flag was in the description.
`flag{hello_world}`

## Weirdo (5)
> This is what a challenge with a non-standard flag will look like. These types of flags are generally used for things like IP addresses or other data that would be a "short answer" style. The challenge will always be marked with a "NON-STANDARD FLAG FORMAT" identifier if it is this way.

> Submit the flag 192.168.1.1/24 to get credit for this challenge.

Same thing, flag is `192.168.1.1/24`. This just tells us some challenges are not in the normal `flag{}` format.





# 1. Cryptography


## Homerun (75)
> Check out 0xFF in the ASCII lookup table...  
> Oh dang, it isn't there. Well I still need to send you that data, not the text but the actual value 0xFF in computer memory.
> Here's an example, decode this, all the data you need is right here: `MZWGCZ33I5XXI5DBJVQWWZKTOVZGKWLPOVEGKYLSIFRG65LUKRUGC5CMN5XGOQTBNRWH2===`

We get a ciphertext `MZWGCZ33I5XXI5DBJVQWWZKTOVZGKWLPOVEGKYLSIFRG65LUKRUGC5CMN5XGOQTBNRWH2===`. This is clearly base32 as we see it consists of only uppercase letters and numbers, ending with `=`. Decoding in CyberChef or any other tool gives `flag{GottaMakeSureYouHearAboutThatLongBall}`

## Mason (75)

> The numbers mason, what do they mean?
> ```66 6c 61 67 7b 63 6f 6d 70 75 74 65 72 3a 69 5f 6f 6e 6c 79 5f 75 6e 64 65 72 73 74 61 6e 64 5f 62 69 6e 61 72 79 5f 64 75 64 65 7d```

Ciphertext consists of 0-9 and a-f, hinting that it's hex. Decoding from hex gives `flag{computer:i_only_understand_binary_dude}`

## Smiley (100)

## Matchmaker (100)

> There are a variety of symmetric cryptosystems out there, but most of them involve a logic block called a XOR. The key is "hab"(UTF8). We're giving you the key and the algorithm, how hard can it be?

> `Dg0DDxoRBz4PHQIKNxIbBQwHHBMbFQ==`

We are given base64, and the XOR key "hab". Using CyberChef we can decrypt and XOR to get the flag.

{{< image src="./img/matchmaker1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}



# 2. Web

## Detective (75)
> Visit the webapp and take a look around, detective: https://erpvlnzxrh.qualifier.hackabit.com/detective





# 3. Programming
# 4. Infrastructure
# 5. Networking
# 6. OSINT