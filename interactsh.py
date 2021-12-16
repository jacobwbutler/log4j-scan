
import argparse
import os
from interactsh import *
import random
import requests
import time
import sys
from urllib import parse as urlparse
import base64
import json
import random
from uuid import uuid4
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import cprint

class interactsh:
    # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
    def __init__(self, config_path="./interactsh-conf.json", overwrite=False, token="", server=""):
        self.headers = {
            "Content-Type": "application/json",
        }
        self.session = requests.session()
        self.session.headers = self.headers
        if os.path.exists(config_path) and not overwrite:
            with open(config_path) as cp:
                config_json = json.load(cp)
                self.server = config_json["server"]
                self.secret = config_json["secret"]
                self.encoded = config_json["pub_encoded"]
                self.public_key = b64decode(self.encoded)
                self.private_key = b64decode(config_json["priv_encoded"])
                self.correlation_id = config_json["correlation_id"]
                self.headers = config_json["headers"]
                self.domain = config_json["domain"]
        else:
            # Register new domain
            rsa = RSA.generate(2048)
            self.public_key = rsa.publickey().exportKey()
            self.private_key = rsa.exportKey()
            self.token = token
            self.server = server.lstrip('.') or 'interact.sh'

            if self.token:
                self.headers['Authorization'] = self.token
            self.secret = str(uuid4())
            self.encoded = b64encode(self.public_key).decode("utf8")
            guid = uuid4().hex.ljust(33, 'a')
            guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
            self.domain = f'{guid}.{self.server}'
            self.correlation_id = self.domain[:20]
            self.register(config_path)

    def register(self, config_path):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise Exception("Can not initiate interact.sh DNS callback client")
        conf_json = {
            "server": self.server,
            "pub_encoded": self.encoded,
            "priv_encoded": b64encode(self.private_key).decode("utf8"),
            "secret": self.secret,
            "correlation_id": self.correlation_id,
            "headers": self.headers,
            "domain": self.domain
        }
        with open(config_path, 'w') as cp:
            json.dump(conf_json, cp)

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.domain}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry

if __name__ == "__main__":
    if sys.argv[1] == 'reset':
        interactsh = interactsh(overwrite=True)
    elif sys.argv[1] == 'pull':
        interactsh = interactsh()
        print(interactsh.pull_logs())