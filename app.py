import nmap
import json
import pprint
import requests
import vulners
import os
from fpdf import FPDF
import translator
from pymongo import MongoClient


def get_vulnerability_description(vulners_api: vulners, vulnerability_ids):
    return vulners_api.get_multiple_bulletins(id=vulnerability_ids, fields=["description"])

def insert_data(nm: nmap.PortScanner, db):
    document_info = {}
    for proto, data in nm.scaninfo().items():
        document_info[proto] = data['services']
    document_info['timestr'] = nm.scanstats()['timestr']
    db.scans.insert_one(document_info)

    print(nm.all_hosts())

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                document = {
                    'ip': host,
                    'hostname': host['hostnames']['name']
                }
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
    # for ip, data in nm.:
    #     document = {
    #         "ip": ip,
    #         "hostnames": data['hostnames'],
    #         "addresses": data['addresses'],
    #         "status": data['status'],
    #         "tcp": data.get('tcp', {})
    #     }
    #     db.scans.insert_one(document)


    
def main():
    client = MongoClient('localhost', 27017)
    db = client['scans']

    vulners_api = vulners.Vulners(api_key=os.getenv('API_KEY'))

    nm = nmap.PortScanner()
    nm.scan(hosts='45.67.229.226-227', arguments='-sS -F -sV --script vulners', sudo=True)
    insert_data(nm, db)
    with open("data.json", "w", encoding="utf-8") as filewrite:
        json.dump(nm.analyse_nmap_xml_scan(), filewrite, ensure_ascii=False, indent=4)
    
    with open("data.json", 'r', encoding='utf-8') as fileread:
        data = json.load(fileread)


    # lis = ["CVE-2023-6548", "CVE-2023-6549"]
    # descriptions= get_vulnerability_description(vulners_api, lis)
    # for cve in descriptions:
    #     text =  descriptions.get(cve).get('description')
    #     text_leng = detect_lang(text, iam_token, folder_id)
    #     print()
    #     print(cve, '\t', text)
    #     print()
    #     print(cve, '\t', translate_description(text, text_leng, folder_id, iam_token))
    # json_data = """
    #     {
    #         "title": "Sample Report",
    #         "header": ["ID", "Name", "Value"],
    #         "data": [
    #             {"ID": "1", "Name": "Item 1", "Value": "123"},
    #             {"ID": "2", "Name": "Item 2", "Value": "456"},
    #             {"ID": "3", "Name": "Item 3", "Value": "789"}
    #         ]
    #     }
    # """


if __name__ == '__main__':
    main()




# print(nm.command_line())
# with open("data.json", "w", encoding="utf-8") as file:
#     json.dump(nm.analyse_nmap_xml_scan(), file, ensure_ascii=False, indent=4)

# print(nm['45.67.229.226']['tcp'][22]['script']['vulners'])
# for host in nm.all_hosts():
#     print('----------------------------------------------------')
#     print('Host : %s (%s)' % (host, nm[host].hostname()))
#     print('State : %s' % nm[host].state())
#     for proto in nm[host].all_protocols():
#         print('----------')
#         print('Protocol : %s' % proto)
#         lport = nm[host][proto].keys()
#         for port in lport:
#             print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))