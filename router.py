#!/usr/bin/python3
import os
import hashlib
import requests
import subprocess
import configparser


class Router:
    def __init__(self, isp=None, ipaddress=None):
        # These credentials will differ per router hardware/isp
        self.default_user = 'admin'
        self.default_password = 'admin'

        self.isp = isp
        self.ipaddress = ipaddress
        self.web_session = requests.session()
        self.sid = None

    def login(self, username=None, password=None, timeout=5):
        if (username, password) == (None, None):
            print(f'Login method was not called with login credentials. Assuming default: {self.default_user}:{self.default_password}')
            username = self.default_user
            password = self.default_password

        # make sure we can at least hit gateway
        try:
            self.web_session.get(f'http://{self.ipaddress}', timeout=timeout)
        except requests.exceptions.ConnectTimeout as exception:
            print(f'Timeout out trying to reach http://{self.ipaddress}')
        response = self.web_session.get(f'http://{self.ipaddress}', timeout=timeout)
        response.raise_for_status()

        ###
        # this part will differ for different routers - need to generalize somehow...
        # for me we'll see a redirect to login form
        ###
        assert '/login.html' in response.url

        # this specultated because I'm too lazy to confirm
        version = response.url.split('/login')[0].split('/')[-1]
        # Instead of relying on redirect with version in url we can also use the GetLatestVersion path which can be requested without authentication
        # version = self.get_latest_version()

        # L72 of login.js
        # //2、输入无误后，提交后台
        # LoginPage.UserData.Password= $.md5(LoginPage.UserData.UserName+":"+LoginPage.UserData.Password);
        prepared_payload_password = hashlib.md5(f'{username}:{password}'.encode()).hexdigest()

        payload = {
            'Password': prepared_payload_password,
            'UserName': username,
            'token': ''  # this changed from 'sessionID' on 2019-01-08 apparently. lol okay 
        }
        headers = {
            'Referer': f'http://192.168.1.1/{version}/login.html',  # apparently this is needed now as of 2019-01-08. without it the response is empty
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }

        response = self.web_session.post(f'http://{self.ipaddress}/{version}/cgi-bin/Login', json=payload, headers=headers)
        response.raise_for_status()
        assert response.json()['Success'] is True, response.json()
        self.sid = response.json()['sessionID']

        payload = {
            'LangType': 'en',
            'token': ''  # this changed from 'sessionID' on 2019-01-08 apparently. lol okay 
        }
        response = self.web_session.post(f'http://{self.ipaddress}/{version}/cgi-bin/SetLangType', json=payload, headers=headers)
        response.raise_for_status()
        assert response.json()['Success'] is True, response.json()

    def get_latest_version(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        response = self.web_session.post(f'http://{self.ipaddress}/cgi-bin/GetLatestVersion', json={}, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'})
        response.raise_for_status()
        return response.json()['Version']


root_directory = os.getcwd()
cfg = configparser.ConfigParser()
configFilePath = os.path.join(root_directory, 'config.cfg')
cfg.read(configFilePath)

# assume something like: "default via 192.168.2.1 dev wlp2s0b1 proto dhcp metric 600" 
ip_route_proc = subprocess.Popen(['ip route | grep default | awk {\'print $3\'}'], stdout=subprocess.PIPE, shell=True)
gateway_ip = ip_route_proc.communicate()[0].decode().strip()

my_router = Router('Spectrum', gateway_ip)
my_router.login(cfg.get('login', 'username'), cfg.get('login', 'password'))
print(my_router.get_latest_version())
