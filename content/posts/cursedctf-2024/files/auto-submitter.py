import requests
import threading
import time
import json
import tqdm
from discord_webhook import DiscordWebhook

correct_flag = "goodFlag"
incorrect_flag = "badFlag"
invalid_token = "badToken"
timeout = "badRateLimit"
already_solved = "badAlreadySolvedChallenge"

thread_count = 0
thread_max = 50

webhook_url = "redacted lmao"

accounts = {}
temp_accounts = {}
flags = {}

successful_submissions = {}

def format_slug(slug):
    return f"https://ctf.cursedc.tf/api/v1/challs/{slug}/submit"

def submit_flag(auth_token, challenge_url, flag):

    headers = {
        'Accept': '*/*',
        'Origin': 'https://ctf.cursedc.tf',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}',
        'Referer': 'https://ctf.cursedc.tf/challs',
        # 'Content-Length': '25',
        'Host': 'ctf.cursedc.tf',
        'Accept-Language': 'en-AU,en;q=0.9',
        'User-Agent': 'REDACTED',
        # 'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }

    json_data = {
        'flag': flag,
    }

    response = requests.post(challenge_url, headers=headers, json=json_data)
    return response

def submit_verify_flag(auth_token, challenge_url, flag):
    global thread_count
    global successful_submissions

    error_count = 0
    while True:
        resp = submit_flag(auth_token, challenge_url, flag)
        try:
            resp = resp.json()
        except Exception as e:
            print(f"error submitting flag {flag} {challenge_url} {auth_token} : {e = } {resp.text = }")
            error_count += 1
            if error_count > 5:
                thread_count -= 1
                return
            continue
        
        if correct_flag == resp['kind']:
            thread_count -= 1
            successful_submissions[auth_token] = True
            return True
        elif incorrect_flag == resp['kind']:
            thread_count -= 1
            return False
        elif timeout == resp['kind']:
            time.sleep(resp['data']['timeLeft'] / 1000)
        elif already_solved == resp['kind']:
            thread_count -= 1
            successful_submissions[auth_token] = True
            return True
        else:
            print(f"unknown response {resp = }")
            thread_count -= 1
            return
        
def submit_flag_for_all_accounts(challenge_url, flag):
    global thread_max
    global thread_count

    webhook = DiscordWebhook(url=webhook_url, content="Starting...")
    webhook.execute()

    count = 0
    for email, auth_token in tqdm.tqdm(accounts.items()):
        while thread_count > thread_max:
            webhook.content = f'''Successful submissions: {len(successful_submissions)}/{count}
Running {thread_count} threads...
'''
            webhook.edit()

            print(f"Thread max reached {thread_count = } {thread_max = }, waiting...")
            time.sleep(10)
    
        x = threading.Thread(target=submit_verify_flag, args=(auth_token, challenge_url, flag))
        thread_count += 1
        x.start()

        count += 1
    
    webhook = DiscordWebhook(url=webhook_url, content=f"FINISHED! (threads might still be running). successful: {len(successful_submissions)}/{count}")
    webhook.execute()

def get_accounts():
    global accounts
    with open("./creds.json") as f:
        accounts = json.load(f)

def check_and_remove_invalid_account(email, auth_token):
    global thread_count

    resp = submit_flag(auth_token, format_slug("osint-geoguessrk"), "test")
    # print(resp.json())
    thread_count -= 1
    try:
        if invalid_token == resp.json()['kind']:
            # print("DELETING!!")
            del temp_accounts[email]
    except Exception as e:
        print(f"Error: {e = } {resp = } {resp.text}")

def remove_invalid_accounts():
    global accounts
    global temp_accounts
    global thread_max
    global thread_count

    temp_accounts = dict(accounts)
    initial_num = len(accounts)

    threads = []
    for email, auth_token in tqdm.tqdm(accounts.items()):
        
        while thread_count > thread_max:
            print(f"Thread max reached {thread_count = } {thread_max = }, waiting...")
            time.sleep(10)
        x = threading.Thread(target=check_and_remove_invalid_account, args=(email, auth_token))
        thread_count += 1
        x.start()
        threads.append(x)

    # wait for all threads to finish
    for x in threads:
        x.join()
        
    accounts = temp_accounts
    final_num = len(accounts)
    print(f"Removed {initial_num - final_num}/{initial_num} invalid accounts.")

    with open("./creds.json", "w") as f:
        f.write(json.dumps(accounts))

def remove_solved_accounts():
    global accounts

    # with open("./success.log") as f:
        # succeeded = json.loads(f.read().replace("'", '"'))
    with open("./success.log") as f:
        succeeded = eval(f.read())

    temp_accounts = dict(accounts)
    for email, auth_token in tqdm.tqdm(accounts.items()):
        if auth_token in succeeded.keys():
            del temp_accounts[email]
    
    accounts = temp_accounts



def get_flags():
    global flags
    with open("./flags.json") as f:
        flags = json.load(f)

def main():
    global accounts, flags

    get_accounts()
    # remove_invalid_accounts()
    remove_solved_accounts()
    get_flags()

    print(f"Number of accounts: {len(accounts)}")
    print(f"Number of flags: {len(flags)}")

    webhook = DiscordWebhook(url=webhook_url, content=f'''Number of accounts: {len(accounts)}''')
    webhook.execute()

    submit_flag_for_all_accounts(format_slug("osint-geoguessr5"), "cursedctf{iceland}")
    
    with open(f"./success_{int(time.time())}.json", "w") as f:
        f.write(json.dumps(successful_submissions))

       

if __name__ == "__main__":
    main()