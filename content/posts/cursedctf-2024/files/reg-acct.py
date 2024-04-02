import requests
import json
import email as eml
from queue import Queue
from threading import Thread
from urllib.parse import unquote
from imapclient import IMAPClient
server = IMAPClient('maybe next time', use_uid=True)
print(server.login('good try', r'haha no'))

def register(num):
    name = f"joseph fan club {num}"
    email = f"ctf+{num}@hexf.me"
    r = requests.post("https://ctf.cursedc.tf/api/v1/auth/register", json=dict(
        email=email,
        name=name
        ))
    print(email, r.text)
    k = r.json()
    assert k["kind"] == "goodVerifySent", f"error: {k}"
    return email

def verify(email):
    verifyToken = get_verification_token(email)
    r = requests.post("https://ctf.cursedc.tf/api/v1/auth/verify", json=dict(
            verifyToken=verifyToken
        ))
    
    k = r.json()
    assert k["kind"] == "goodRegister", f"error: {k}"

    return (email, k["data"]["authToken"])

v_tokens = dict()

def get_verification_token(email):
    global v_tokens
    while True:
        if email in v_tokens:
            return v_tokens[email]

        server.select_folder("INBOX")
        messages = server.search(['FROM', 'ctf@cursedc.tf'])
        print('searching emails')
        fetched = server.fetch(messages[:10000], ['RFC822']) | server.fetch(messages[10000:], ['RFC822'])
        print('sorting through emails')
        for msgid, message_data in fetched.items():
            if b"RFC822" not in message_data: continue
            email_message = eml.message_from_bytes(message_data[b"RFC822"])
            for part in email_message.walk():
                pl = part.get_payload(decode=True)
                if part.get_content_type() == "text/plain":
                    token = pl.split(b"?token=")[1].split(b"\r\n\r\n")[0]
                    token = token.replace(b"\r\n", b"").decode()
                    token = unquote(token)
                    em = email_message['to']
                    v_tokens[em] = token
        
        if email == "placeholder":
            print(v_tokens)
            return None
        



clf = open("creds.json", "r")
cred_list = json.load(clf)
clf.close()

#cred_list = {k:v for k,v in cred_list.items() if v != "unverified"}

def do_reg(q):
    global cred_list
    while not q.empty():
        try:
            em = register(q.get())
            cred_list[em] = "unverified"
        except:
            pass
        q.task_done()

def do_ver(q):
    global cred_list
    while not q.empty():
        em = q.get()
        try:
            em, at = verify(em)
            cred_list[em] = at
            print(em, at)
        except:
            pass

        q.task_done()

reg_queue = Queue()
ver_queue = Queue()

get_verification_token("placeholder")
print("registering")
for n in range(1000, -10000):
    e = f"ctf+{n}@hexf.me"
    if e not in cred_list and e not in v_tokens:
        reg_queue.put(n)

for i in range(32):
  worker = Thread(target=do_reg, args=(reg_queue,))
  worker.setDaemon(True)
  worker.start()

reg_queue.join()

with open("creds.json", "w") as f:
    json.dump(cred_list, f)

print("verifying")

for em in v_tokens.keys():
    if (em not in cred_list or cred_list[em] == "unverified"):
        ver_queue.put(em)


for i in range(32):
  worker = Thread(target=do_ver, args=(ver_queue,))
  worker.setDaemon(True)
  worker.start()

ver_queue.join()
    
with open("creds.json", "w") as f:
    json.dump(cred_list, f)

exit(0)
for em,tk in cred_list.items():
    if tk != "unverified": continue
    print(em)
#    cred_list[em] = verify(em)
    
    with open("creds.json", "w") as f:
        json.dump(cred_list, f)
