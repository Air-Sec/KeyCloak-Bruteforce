import requests
from bs4 import BeautifulSoup
import pdb
import re
import urllib3

data = {
    "kc_realm": '',
    "kc_clientid": '',
    "kc_redirect_uri": '',
    "auth_session_id": '',
    "kc_restart": '',
    "session_code": '',
    "execution": '',
    "tab_id": '',
    'code': '',
    "kc_identity": '',
    "kc_session": ''
    }

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_config(url):
    print('[*] Request 1 - Getting config.json')
    reply = requests.get(url)

    #pdb.set_trace()

    if reply.status_code != 200:
        print('\033[0;31m[-]\033[0m Error getting config.json')
        exit()

    config = reply.json()

    print('\033[0;34m[+]\033[0m Retrieved Keycloak_Realm={}'.format(config['Keycloak_Realm']))
    print('\033[0;34m[+]\033[0m Retrieved Keycloak_Client_Id={}'.format(config['Keycloak_Client_Id']))
    print('\033[0;34m[+]\033[0m Retrieved Keycloak_Redirect_Uri={}'.format(config['Keycloak_Redirect_Uri']))

    return config

def prepare_auth(url):

    print('[*] Request 2 - Grabbing session IDs')

    resp = requests.get(url)

    if resp.status_code != 200:
        print('\033[0;31m[-]\033[0m  Error getting auth response')
        exit()

    data['auth_session_id'] = resp.cookies['AUTH_SESSION_ID']
    data['kc_restart'] = resp.cookies['KC_RESTART']

    soup = BeautifulSoup(resp.text, 'html.parser')

    result = re.search('(?:session_code=)(.*?)(?:&)', soup.find_all('form')[0].attrs['action'])
    data['session_code'] = result.group(1)

    result = re.search('(?:execution=)(.*?)(?:&)', soup.find_all('form')[0].attrs['action'])
    data['execution'] = result.group(1)

    result = re.search('(?:tab_id=)(.*)', soup.find_all('form')[0].attrs['action'])
    data['tab_id'] = result.group(1)

    print('\033[0;34m[+]\033[0m  Retrieved AUTH_SESSION_ID={}'.format(data['auth_session_id']))
    print('\033[0;34m[+]\033[0m Retrieved KC_RESTART={}'.format(data['kc_restart']))
    print('\033[0;34m[+]\033[0m  Retrieved session_code={}'.format(data['session_code']))
    print('\033[0;34m[+]\033[0m  Retrieved execution={}'.format(data['execution']))
    print('\033[0;34m[+]\033[0m  Retrieved tab_id={}'.format(data['tab_id']))

    #pdb.set_trace()

def send_auth(url, username, password):

    print('[*] Request 3 - Sending username and password')

    cookies = {
        'AUTH_SESSION_ID': data['auth_session_id'],
        'AUTH_SESSION_ID_LEGACY': data['auth_session_id'],
        'KC_RESTART': data['kc_restart']}

    body = { 'username': username,
             'password': password,
             'credentialId': ''}

    proxies = {'http':'http://192.168.56.1:8080', 'https':'http://192.168.56.1:8080'}
    resp = requests.post(url, cookies=cookies, data=body, proxies={'https':'http://192.168.56.1:8080'}, allow_redirects=False, verify=False)
    #exit()
    #pdb.set_trace()
    header = resp.headers['Location']
    result = re.search('(?:code=)(.*)', header)
    data['code'] = result.group(1)
    data['kc_identity'] = resp.cookies['KEYCLOAK_IDENTITY']
    data['kc_session'] = resp.cookies['KEYCLOAK_SESSION']

    print('\033[0;34m[+]\033[0m  Retrieved code={}'.format(data['code']))
    print('\033[0;34m[+]\033[0m  Retrieved KEYCLOAK_IDENTITY={}'.format(data['kc_identity']))
    print('\033[0;34m[+]\033[0m  Retrieved KEYCLOAK_SESSION={}'.format(data['kc_session']))

    #pdb.set_trace()

def get_token(url):

    print('\033[1;32;40m[+]\033[0m Request 4 - retrieving Authorization Bearer token')

    cookies = {
        'AUTH_SESSION_ID': data['auth_session_id'],
        'AUTH_SESSION_ID_LEGACY': data['auth_session_id'],
        'KEYCLOAK_IDENTITY': data['kc_identity'],
        'KEYCLOAK_IDENTITY_LEGACY': data['kc_identity'],
        'KEYCLOAK_SESSION': data['kc_session'],
        'KEYCLOAK_SESSION_LEGACY': data['kc_session']}

    body = { 'grant_type': 'authorization_code',
             'code': data['code'],
             'redirect_uri': 'https://TARGETDOMAIN/signin',
             'client_id': data['kc_clientid']}

    proxies = {'http':'http://192.168.56.1:8080', 'https':'http://192.168.56.1:8080'}
    resp = requests.post(url, cookies=cookies, data=body, proxies={'https':'http://192.168.56.1:8080'}, allow_redirects=False, verify=False)

    print('\033[1;32;40m\033[1m[+]\033[0m  Retrieved session tokens below')
    print('\033[1;32;40m\033[1m' + str(resp.json()) + '\033[0m')
    #print('\033[0;34m[+]\033[0m  Retrieved KEYCLOAK_SESSION={}'.format(data['kc_session']))

    #pdb.set_trace()


def main():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    print("")
    passwords = ['a', 'a', 'a', password]
    count = 0
   
    for password in passwords:
        try:
            count+=1
            print('Password attempt ' + str(count) + ': ' + password)
            url1 = 'https://TARGETDOMAIN/assets/config.json'
            config = get_config(url1)
            data['kc_realm'] = config['Keycloak_Realm']
            data['kc_clientid'] = config['Keycloak_Client_Id']
            data['kc_redirect_uri'] = config['Keycloak_Redirect_Uri']
            url2_base = 'https://TARGETDOMAIN/auth/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri={}'
            url2 = url2_base.format(data['kc_realm'], data['kc_clientid'], data['kc_redirect_uri'])
            prepare_auth(url2)
            url3_base = 'https://TARGETDOMAIN/auth/realms/{}/login-actions/authenticate?session_code={}&execution={}&client_id={}&tab_id={}'
            url3 = url3_base.format(data['kc_realm'],
                            data['session_code'],
                            data['execution'],
                            data['kc_clientid'],
                            data['tab_id'])
 
            send_auth(url3, username, password)
            print('\033[1;32;40m[+]\033[0m Password correct')
            print('\033[1;32;40m[+]\033[0m Getting tokens')
        
            url4 = 'https://TARGETDOMAIN/auth/realms/qashqade_realm/protocol/openid-connect/token'
            get_token(url4)
        except Exception as exec:
            if KeyError:
                print('\033[0;31m[-]\033[0m ' + str(exec) + ' header not found')
            print('\033[0;31m[-]\033[0m Incorrect password\n')
            pass


if __name__ == "__main__":
    main()

