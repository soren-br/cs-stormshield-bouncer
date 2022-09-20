from asyncio import protocols
from urllib import response
import requests
import json
import pandas as pd 

from stormshield.sns.sslclient import SSLClient

class CrowdSecConnector():

    def __init__(self, url, token):

        self.url = url
        self.token = token

    def get_data(self):
        
        headers = {"X-Api-Key" : "{}".format(self.token)}
        response = requests.get("{}/v1/decisions/stream?startup=false".format(self.url), headers=headers)

        if response.status_code == 200:
            self.data = json.loads(response.text)
        else:
            return 'Unable to communicate with the Crowdsec server (Error : {})'.format(response.status_code)

    def get_new_ip(self):

        if self.data['new'] == None:
            return None
        else:
            df_new_ip = pd.DataFrame(data=self.data['new'])
            df_new_ip = df_new_ip[(df_new_ip['origin'] == 'cscli')]
            return df_new_ip['value'].tolist()

    def get_deleted_ip(self):
        
        if self.data['deleted'] == None:
            return None
        else:
            df_deleted_ip = pd.DataFrame(data=self.data['deleted'])
            df_deleted_ip = df_deleted_ip[(df_deleted_ip['origin'] == 'cscli')]
            return df_deleted_ip['value'].tolist()

class StormshieldConnector():

    def __init__(self, ip, port, username, password, group_name):

        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.group_name = group_name

        self.client = self.get_auth()

    def get_auth(self):

        client = SSLClient(
            host=self.ip,
            port=self.port,
            user=self.username,
            password=self.password,
            sslverifypeer=False,
            sslverifyhost=False
        )

        return client
    
    def create_object(self,ips):
        
        for ip in ips:
            name_of_obj = "crowdsec_{}".format(ip)
            self.client.send_command("MODIFY ON FORCE")
            commande = '''CONFIG OBJECT HOST NEW name="{}" comment="IP Blocked by Crowdsec" ip="{}" resolve=static mac="" update=1'''.format(name_of_obj, ip)
            response = self.client.send_command(commande)

    def add_to_group(self,ips):

        self.client.send_command("MODIFIY ON FORCE")
        for ip in ips:
            name_of_obj = "crowdsec_{}".format(ip)
            commande = '''CONFIG OBJECT GROUP ADDTO group={} node={}'''.format(self.group_name, name_of_obj)
            self.client.send_command(commande)
        
        self.client.send_command("CONFIG OBJECT ACTIVATE")

    def del_to_group(self,ips):
        
        self.client.send_command("MODIFY ON FORCE")
        for ip in ips:
            name_of_obj = "crowdsec_{}".format(ip)
            commande = '''CONFIG OBJECT GROUP REMOVEFROM group={} node={}'''.format(self.group_name, name_of_obj)
            self.client.send_command(commande)
        
        self.client.send_command("CONFIG OBJECT ACTIVATE")
    
    def del_object(self,ips):
        self.client.send_command("MODIFY ON FORCE")
        for ip in ips:
            name_of_obj = "crowdsec_{}".format(ip)
            commande = '''CONFIG OBJECT HOST DELETE name={} force=1'''.format(name_of_obj)
            self.client.send_command(commande)

    def disconnect(self):

        self.client.disconnect()
        
if __name__ == '__main__':

    with open('config.json') as json_config_file:
        json_conf_data = json.load(json_config_file)

    crowdsec_url = json_conf_data['crowdsec']['url']
    crowdsec_token = json_conf_data['crowdsec']['token']

    stormshield_ip = json_conf_data['stormshield']['ip']
    stormshield_port = json_conf_data['stormshield']['port']
    stormshield_username = json_conf_data['stormshield']['username']
    stormshield_password = json_conf_data['stormshield']['password']
    stormshield_group_name = json_conf_data['stormshield']['groupe-name']

    crowdsecconnector = CrowdSecConnector(crowdsec_url,crowdsec_token)
    crowdsecconnector.get_data()

    ip_blocked = crowdsecconnector.get_new_ip()
    ip_unblocked = crowdsecconnector.get_deleted_ip()

    stormshieldconnector = StormshieldConnector(stormshield_ip, stormshield_port, stormshield_username, stormshield_password)
    
    if ip_blocked == None:
        pass
    else:
        stormshieldconnector.create_object(ip_blocked)
        stormshieldconnector.add_to_group(ip_blocked)
    
    if ip_unblocked == None:
        pass
    else:
        stormshieldconnector.del_to_group(ip_unblocked)
        stormshieldconnector.del_object(ip_unblocked)

    stormshieldconnector.disconnect()