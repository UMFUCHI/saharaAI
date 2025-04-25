import cloudscraper
from eth_account import Account
from eth_account.messages import encode_defunct
import string
import random
import datetime
import requests
import time
from web3 import Web3
import logging
from config import CAPSOLVER_API_KEY, random_wallets, min_wait_time, max_wait_time
import threading
from threading import Lock


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
counter, lock = 0, Lock()


class captcha():
    def turnstile(self, account_index):
        while True:
            try:
                client = requests.Session()
                CAPSOLVER_API_ENDPOINT = "https://api.capsolver.com/createTask"
                WEBSITE_URL = "https://faucet.saharalabs.ai/"

                data = {
                    "clientKey": CAPSOLVER_API_KEY,
                    "task": {
                        "type": "AntiTurnstileTaskProxyLess",
                        "websiteURL": WEBSITE_URL,
                        "websiteKey": "0x4AAAAAAA8hNPuIp1dAT_d9",
                    }
                }

                task_id_response = client.post(CAPSOLVER_API_ENDPOINT, json=data)
                task_id = task_id_response.json()["taskId"]
                time.sleep(5)
                turnstile_response = client.post(
                    "https://api.capsolver.com/getTaskResult",
                    json={"clientKey": CAPSOLVER_API_KEY, "taskId": task_id}
                ).json()
                return turnstile_response['solution']['token']
            except Exception as e:
                logger.error(f"Кошелек [{account_index}] - Ошибка в turnstile: {e}")
                continue

    def geetest(self, account_index):
        while True:
            try:
                client = requests.Session()
                CAPSOLVER_API_ENDPOINT = "https://api.capsolver.com/createTask"
                WEBSITE_URL = "https://app.galxe.com/quest/SaharaAI/GCNLYtpFM5"

                data = {
                    "clientKey": CAPSOLVER_API_KEY,
                    "task": {
                        "type": "GeeTestTaskProxyless",
                        "websiteURL": WEBSITE_URL,
                        "captchaId": "244bcb8b9846215df5af4c624a750db4",
                    }
                }

                task_id_response = client.post(CAPSOLVER_API_ENDPOINT, json=data)
                task_id = task_id_response.json()["taskId"]
                time.sleep(random.randint(5, 10))
                geetest_response = client.post(
                    "https://api.capsolver.com/getTaskResult",
                    json={"clientKey": CAPSOLVER_API_KEY, "taskId": task_id}
                ).json()
                if 'solution' in geetest_response:
                    return geetest_response
                else:
                    continue
            except Exception as e:
                logger.error(f"Кошелек [{account_index}] - Ошибка в geetest: {e}")
                continue


def faucet(public, proxy, account_index, scraper):
    faucet_headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'Connection': 'keep-alive',
        'cf-turnstile-response': captcha().turnstile(account_index)
    }
    faucet_response = scraper.post(
        'https://faucet-api.saharaa.info/api/claim2',
        json={"address": public},
        headers=faucet_headers,
        proxies=proxy
    )
    try:
        logger.info(f"Кошелек [{account_index}] - Запрос на Faucet: {faucet_response.json()['msg']}")
    except:
        logger.info(f"Кошелек [{account_index}] - Ответ Faucet: {faucet_response.json()}")


def galxe(private_key, public, proxy, account_index, scraper):
    galxe_api = 'https://graphigo.prd.galaxy.eco/query'

    nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    issued_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    expiration_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).isoformat().replace("+00:00", "Z")
    text = f"""app.galxe.com wants you to sign in with your Ethereum account:\n{public}\n\nSign in with Ethereum to the app.\n\nURI: https://app.galxe.com\nVersion: 1\nChain ID: 1625\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration_time}"""

    signed_message = Account.sign_message(encode_defunct(text=text), private_key=private_key)

    derived_address = Account.from_key(private_key).address
    if derived_address.lower() != public.lower():
        logger.error(
            f"Кошелек [{account_index}] - Приватный ключ не соответствует адресу: {public} != {derived_address}")
        return

    galxe_signIn_payload = {
        "operationName": "SignIn",
        "variables": {
            "input": {
                "address": public,
                "signature": '0x' + signed_message.signature.hex(),
                "message": text,
                "addressType": "EVM",
                "publicKey": "56"
            }
        },
        "query": "mutation SignIn($input: Auth) {\n  signin(input: $input)\n}"
    }
    headers = {'content-type': 'application/json'}

    token_response = scraper.post(galxe_api, json=galxe_signIn_payload, headers=headers, proxies=proxy)
    token = token_response.json()

    if 'data' in token and 'signin' in token['data']:
        auth_token = token['data']['signin']
        headers["authorization"] = f"{auth_token}"

        geetest_response = captcha().geetest(account_index)
        galxe_daily_sahara_blog_payload = {
            "operationName": "AddTypedCredentialItems",
            "variables": {
                "input": {
                    "credId": "507361624877694976",
                    "campaignId": "GCNLYtpFM5",
                    "operation": "APPEND",
                    "items": [f"EVM:{public}"],
                    "captcha": {
                        "lotNumber": geetest_response['solution']['lot_number'],
                        "captchaOutput": geetest_response['solution']['captcha_output'],
                        "passToken": geetest_response['solution']['pass_token'],
                        "genTime": geetest_response['solution']['gen_time']
                    }
                }
            },
            "query": "mutation AddTypedCredentialItems($input: MutateTypedCredItemInput!) {\n  typedCredentialItems(input: $input) {\n    id\n    __typename\n  }\n}"
        }
        blog_response = scraper.post(galxe_api, json=galxe_daily_sahara_blog_payload, headers=headers, proxies=proxy)
        blog_data = blog_response.json()

        if blog_data == {'data': {'typedCredentialItems': {'id': '507361624877694976', '__typename': 'Cred'}}}:
            logger.info(f"Кошелек [{account_index}] - Blog квест успешно обработан")
        else:
            logger.error(f"Кошелек [{account_index}] - Blog ошибка: {blog_data}")

        geetest_response2 = captcha().geetest(account_index)
        galxe_daily_sahara_x_payload = {
            "operationName": "AddTypedCredentialItems",
            "variables": {
                "input": {
                    "credId": "505649247018811392",
                    "campaignId": "GCNLYtpFM5",
                    "operation": "APPEND",
                    "items": [f"EVM:{public}"],
                    "captcha": {
                        "lotNumber": geetest_response2['solution']['lot_number'],
                        "captchaOutput": geetest_response2['solution']['captcha_output'],
                        "passToken": geetest_response2['solution']['pass_token'],
                        "genTime": geetest_response2['solution']['gen_time']
                    }
                }
            },
            "query": "mutation AddTypedCredentialItems($input: MutateTypedCredItemInput!) {\n  typedCredentialItems(input: $input) {\n    id\n    __typename\n  }\n}"
        }
        x_response = scraper.post(galxe_api, json=galxe_daily_sahara_x_payload, headers=headers, proxies=proxy)
        x_data = x_response.json()

        if x_data == {'data': {'typedCredentialItems': {'id': '505649247018811392', '__typename': 'Cred'}}}:
            logger.info(f"Кошелек [{account_index}] - X квест успешно обработан")
        else:
            logger.error(f"Кошелек [{account_index}] - X ошибка: {x_data}")
    else:
        logger.error(f"Кошелек [{account_index}] - Токен Galxe не получен: {token}")


def transaction(private_key, public, account_index):
    try:
        w3 = Web3(Web3.HTTPProvider("https://testnet.saharalabs.ai"))
        assert w3.is_connected(), "Ошибка подключения к Sahara!"
        amount = w3.to_wei(random.uniform(0.00001, 0.001), "ether")
        nonce = w3.eth.get_transaction_count(w3.to_checksum_address(public))
        if random_wallets == True:
            wallet = Account.create().address
        else:
            with open('public.txt', 'r') as file:
                wallet = Web3().eth.account.from_key(random.choice(private_keys)).address
        tx = {
            "from": public,
            "to": wallet,
            "value": amount,
            "gas": 31500,
            "gasPrice": w3.eth.gas_price,
            "nonce": nonce,
            "chainId": 313313,
        }

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        logger.info(f"Кошелек [{account_index}] - Транзакция отправлена: 0x{tx_hash.hex()}")
    except Exception as ex:
        logger.error(f"Кошелек [{account_index}] - Ошибка транзакции: {ex}")


def bearer(headers_sahara, private_key, public, proxy, account_index, scraper):
    for _ in range(10):
        challenge_api = 'https://legends.saharalabs.ai/api/v1/user/challenge'
        challenge_payload = {"address": public, 'timestamp': time.time() * 1000}
        r = scraper.post(challenge_api, json=challenge_payload, headers=headers_sahara, proxies=proxy)
        if 'challenge' in r.json():
            challenge = r.json()['challenge']

            wallet = 'https://legends.saharalabs.ai/api/v1/login/wallet'
            signed_message = Account.sign_message(encode_defunct(text=f"Sign in to Sahara!\nChallenge:{challenge}"), private_key=private_key)
            wallet_payload = {
                "address": public,
                "sig": '0x' + signed_message.signature.hex(),
                "referralCode": "YMZC0Y",
                "walletUUID": "b34e7d74-c02c-4b2c-a30a-030555241d29",
                "walletName": "Rabby Wallet",
                'timestamp': time.time() * 1000
            }

            bearer_token = scraper.post(wallet, json=wallet_payload, headers=headers_sahara, proxies=proxy)
            if bearer_token:
                return bearer_token.json()['accessToken']
            else:
                logger.error(f"Кошелек [{account_index}] - Токен Sahara не получен")


def sahara_daily(headers, proxy, account_index, scraper):
    time.sleep(random.randint(80, 120))
    transaction_api = 'https://legends.saharalabs.ai/api/v1/task/flush'
    claim_api = 'https://legends.saharalabs.ai/api/v1/task/claim'
    taskIDs = ['1001', '1002', '1004']
    for taskID in taskIDs:
        sahara_daily_payload = {'taskID': taskID, 'timestamp': time.time() * 1000}
        for _ in range(2):
            scraper.post(transaction_api, json=sahara_daily_payload, headers=headers, proxies=proxy)
            dailyBatch_response = scraper.post(
                'https://legends.saharalabs.ai/api/v1/task/dataBatch',
                json={'taskIDs': [taskID], 'timestamp': time.time() * 1000},
                headers=headers,
                proxies=proxy
            )
            time.sleep(random.randint(1, 3))
            sahara_daily_response = scraper.post(
                claim_api, json=sahara_daily_payload, headers=headers, proxies=proxy
            ).json()
            if isinstance(sahara_daily_response, list) and 'amount' in sahara_daily_response[0]:
                logger.info(f"Кошелек [{account_index}] - Получено поинтов: {sahara_daily_response[0]['amount']}")
                break
            elif sahara_daily_response == {'code': -1, 'message': f'reward of task: {taskID} has been claimed'}:
                if taskID == '1001':
                    logger.info(f"Кошелек [{account_index}] - уже склеймил Blog")
                    break
                elif taskID == '1002':
                    logger.info(f"Кошелек [{account_index}] - уже склеймил X")
                    break
                elif taskID == '1004':
                    logger.info(f"Кошелек [{account_index}] - уже склеймил Transaction")
                    break
            else:
                if taskID == '1001':
                    logger.error(f"Кошелек [{account_index}] - Ошибка Blog: {sahara_daily_response}")
                elif taskID == '1002':
                    logger.error(f"Кошелек [{account_index}] - Ошибка X: {sahara_daily_response}")
                elif taskID == '1004':
                    logger.error(f"Кошелек [{account_index}] - Ошибка Transaction: {sahara_daily_response}")

            time.sleep(random.randint(1, 60))


def info(headers, scraper, account_index):
    for _ in range(3):
        responce = scraper.post('https://legends.saharalabs.ai/api/v1/user/info', headers=headers, json={'timestamp': time.time() * 1000})
        if responce.status_code == 200:
            logger.info(f"Кошелек [{account_index}] - количество поинтов: {responce.json()['shardAmount']}")
            break
        else:
            logger.error(f"Кошелек [{account_index}] - количество поинтов: {responce.json()['shardAmount']}")
            time.sleep(3)
            continue


def process_account(private_key, proxy, task, account_index):
    headers_sahara = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'authorization': 'Bearer null',
        'content-type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
    }
    scraper = cloudscraper.create_scraper()
    public = Web3().eth.account.from_key(private_key).address
    logger.info(f"Кошелек [{account_index}] - Начало обработки: {public}")
    if task in ['4', '2']:
        bearer_token = bearer(headers_sahara, private_key, public, proxy, account_index, scraper)
        headers = {**headers_sahara, 'authorization': f'Bearer {bearer_token}'}

    try:
        match task:
            case '1': faucet(public, proxy, account_index, scraper)
            case '2':
                galxe(private_key, public, proxy, account_index, scraper)
                transaction(private_key, public, account_index)
                sahara_daily(headers, proxy, account_index, scraper)
            case '3': transaction(private_key, public, account_index)
            case '4':
                info(headers, scraper, account_index)
    except Exception as e:
        logger.error(f"Кошелек [{account_index}] - Ошибка: {e}")


def worker(keys, proxies, task, total):
    global counter
    while True:
        with lock:
            if counter >= total: break
            idx = counter
            counter += 1
        proxy = {'http': f"http://{proxies[idx % len(proxies)]}", 'https': f"http://{proxies[idx % len(proxies)]}"}
        delay = random.uniform(min_wait_time, max_wait_time)
        time.sleep(delay)
        process_account(keys[idx], proxy, task, idx)


if __name__ == '__main__':
    with open('privateKey.txt') as f:
        private_keys = f.read().splitlines()
    with open('proxy.txt') as f:
        proxies = f.read().splitlines()

    task = input("1. Faucet Claim\n2. Daily quests\n3. Transaction only\n4. Account info\n\nOnly num: ")
    threads = min(int(input("Потоки: ")), len(private_keys))

    for i in range(threads):
        threading.Thread(target=worker, args=(private_keys, proxies, task, len(private_keys))).start()

    for t in threading.enumerate():
        if t != threading.current_thread(): t.join()

    logger.info("Готово")
