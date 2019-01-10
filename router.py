#!/usr/bin/python3
import os
import time
import hashlib
import requests
import subprocess
import configparser


class Router:
    def __init__(self, isp=None, ipaddress=None, encrypted_token=None):
        # These credentials will differ per router hardware/isp
        self.default_user = 'admin'
        self.default_password = 'admin'

        self.isp = isp
        self.ipaddress = ipaddress
        self.web_session = requests.session()
        self.sid = None
        self.key = None
        self.version = None
        self.token = None
        self.encrypted_token = encrypted_token  # for ease for now

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
        self.version = response.url.split('/login')[0].split('/')[-1]
        # Instead of relying on redirect with version in url we can also use the GetLatestVersion path which can be requested without authentication
        # self.version = self.get_latest_version()
        self.get_latest_version()
        self.get_redirect_action()
        self.translate()

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
            'Referer': f'http://192.168.1.1/{self.version}/login.html',  # apparently this is needed now as of 2019-01-08. without it the response is empty
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }

        response = self.web_session.post(f'http://{self.ipaddress}/{self.version}/cgi-bin/Login', json=payload, headers=headers)
        response.raise_for_status()
        assert response.json()['Success'] is True, response.json()
        print('Logged in!')
        self.sid = response.json()['sessionID']

        self.set_lang_type()
        self.key = self.get_key()
        self.get_config_status()
        self.get_lan_basic()
        self.get_login_status()
        self.get_nv_info()
        self.get_fw_info()
        self.get_opr_mode()
        self.get_area()
        self.token = self.get_token()

    def get_encrypted_token(self):
        if self.encrypted_token is None:
            print('Getting encrypted token')
        return self.encrypted_token

    def reboot(self):
        """
        TODO need to implement des to encrypt token with key to get token for payload
        encrypt(self.get_token())
        encrypt = function (msg) {
        // 获取key
        var key = w.Global.key;
        // 如果key或者message不存在，直接返回空字符串
        if (!key || !msg) {
            return "";
        }
        // 返回加密结果
        return stringToHex(des(key, msg, 1, 0));
        };
        script/lib/encrypt_utils.js?rev=et234345bc719125gy
        """
        # GET UPGRADE STATUS
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        response = self.web_session.post(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetUpGradeStatus', json={'token': self.get_encrypted_token()}, headers=headers)
        response.raise_for_status()
        assert 'SystemUpgrade' in list(response.json().keys()), response.json()
        # response.json()

        response = self.web_session.post(f'http://{self.ipaddress}/{self.version}/cgi-bin/Reboot', json={'token': self.get_encrypted_token()}, headers=headers)
        response.raise_for_status()
        print(response.json())
        assert response.json()['Success'], response.json()
        return response.json()

    def clear_client_access_control_list(self):
        self.set_client_access_control_list([])

    def set_client_access_control_list(self, mac_address_list):
        """
        mac_address_list: [xx:xx:xx:xx:xx, xx:xx:xx:xx:xx, xx:xx:xx:xx:xx]
        """
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        acl_clients = []
        for mac in mac_address_list:
            acl_clients.append({'Mac': mac})
        payload = {
            'Client': acl_clients
            'IsEnable': "1",
            'token': self.get_encrypted_token
        }
        response = self.web_session.post(f'http://{self.ipaddress}/{self.version}/cgi-bin/SetCliACL', json={'token': self.get_encrypted_token()}, headers=headers)
        response.raise_for_status()
        assert response.json()['Success'], response.json()
        return response.json()


    def get_client_info(self):
        # nice method
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetClientInfo', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'Clients' in list(response.json().keys()), response.json()
        return response.json()

    def get_quick_settings(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetQuickSetting', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert '2_4G_ath_enable' in list(response.json().keys()), response.json()
        return response.json()

    def get_token(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetToken', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'token' in list(response.json().keys()), response.json()
        return response.json()['token']

    def get_area(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetArea', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'Region' in list(response.json().keys()), response.json()
        return response.json()

    def get_opr_mode(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetOprMode', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'OprMode' in list(response.json().keys()), response.json()
        return response.json()

    def get_fw_info(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetFwInfo', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'FwVer' in list(response.json().keys()), response.json()
        return response.json()

    def get_nv_info(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetNvInfo', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert '2_4G_WLAN' in list(response.json().keys()), response.json()
        return response.json()

    def get_login_status(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetLoginStatus', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'Login' in list(response.json().keys()), response.json()
        return response.json()  # sessionID

    def get_lan_basic(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetLanBasic', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'Ip' in list(response.json().keys()), response.json()
        return response.json()

    def get_config_status(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetConfigStatus', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'ConfigStatus' in list(response.json().keys()), response.json()
        return response.json()

    def get_key(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetKey', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert response.json()['Key'], response.json()
        return response.json()['Key']

    def get_latest_version(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        response = self.web_session.post(f'http://{self.ipaddress}/cgi-bin/GetLatestVersion', json={}, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'})
        response.raise_for_status()
        return response.json()['Version']

    def get_redirect_action(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',  # apparently this is needed now as of 2019-01-08. without it the response is empty
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetRedirectAction', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'action' in list(response.json().keys()), response.json()
        return response.json()

    def get_lang_type(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',  # apparently this is needed now as of 2019-01-08. without it the response is empty
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        epoch_ms = int(time.time()*1000)
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/cgi-bin/GetLangType', params={'_': epoch_ms}, headers=headers)
        response.raise_for_status()
        assert 'LangType' in list(response.json().keys()), response.json()
        return response.json()

    def set_lang_type(self, lang='en'):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',  # apparently this is needed now as of 2019-01-08. without it the response is empty
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        payload = {
            'LangType': lang,
            'token': ""
        }
        response = self.web_session.post(f'http://{self.ipaddress}/{self.version}/cgi-bin/SetLangType', json=payload, headers=headers)
        response.raise_for_status()
        assert response.json()['Success'], response.json()
        return response.json()

    def translate(self):
        headers = {
            'Referer': f'http://192.168.1.1/{self.version}/login.html',  # apparently this is needed now as of 2019-01-08. without it the response is empty
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
        }
        response = self.web_session.get(f'http://{self.ipaddress}/{self.version}/translate/{self.get_lang_type()["LangType"]}', headers=headers)
        response.raise_for_status()
        assert response.json(), response.json()
        return response.json()


root_directory = os.getcwd()
cfg = configparser.ConfigParser()
configFilePath = os.path.join(root_directory, 'config.cfg')
cfg.read(configFilePath)

# assume something like: "default via 192.168.2.1 dev wlp2s0b1 proto dhcp metric 600" 
ip_route_proc = subprocess.Popen(['ip route | grep default | awk {\'print $3\'}'], stdout=subprocess.PIPE, shell=True)
gateway_ip = ip_route_proc.communicate()[0].decode().strip()

my_router = Router('Spectrum', gateway_ip, cfg.get('login', 'encrypted_token'))
my_router.login(cfg.get('login', 'username'), cfg.get('login', 'password'))
my_router.reboot()
