from multiprocessing import Pool, Semaphore
import nmap
import json
import pprint
import requests
import vulners
import os
from fpdf import FPDF
import translator
from pymongo import MongoClient
from datetime import datetime
import subprocess
import gis
import genpdf
max_concurrent_scans = 5  # Определяем максимальное количество одновременных задач
semaphore = Semaphore(max_concurrent_scans)

def get_vulnerability_description(vulners_api: vulners.Vulners, vulnerability_ids):
    return vulners_api.get_multiple_bulletins(id=vulnerability_ids, fields=['description'])

def valid_script(data):
    data = data.get('vulners', None)
    if not data:
        return
    lines = data.strip().split('\n') 
    list_of_lists = []

    for line in lines[1:]:
        elements = line.strip().split('\t') 
        if elements:
            list_of_lists.append(elements) 
    return list_of_lists


def insert_data(nm: nmap.PortScanner, collection):
    with open("data.json", "w", encoding="utf-8") as filewrite:
        json.dump(nm.analyse_nmap_xml_scan(), filewrite, ensure_ascii=False, indent=4)
    document_info = {}
    if not collection.find():
        for proto, data in nm.scaninfo().items():
            if data.get('services', None):
                document_info[proto] = data['services']
        document_info['timestr'] = nm.scanstats().get('timestr', None)
        collection.insert_one(document_info)
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port].get('script', None):
                    valid_script_result = valid_script(nm[host][proto][port]['script'])
                else:
                    valid_script_result = None
                document = {
                    'ip': host,
                    'hostname': [dic['name'] for dic in nm[host]['hostnames']],
                    'status': nm[host]['status']['state'],
                    'protocol': proto,
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    "product": nm[host][proto][port]['product'] if nm[host][proto][port]['product'] != '' else None,
                    "version": nm[host][proto][port]['version'] if nm[host][proto][port]['version'] != '' else None,
                    'script': valid_script_result
                }
                collection.insert_one(document)

def main():
    # genpdf.mainpdf()
    client = MongoClient('localhost', 27017)
    db = client['scans']
    hosts = '45.67.229.226'
    lst_nm = gis.main_scans(hosts)

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    collection_name = f'scans_{timestamp}'
    collection = db[collection_name]
    for nm in lst_nm:   
        insert_data(nm, collection)
    genpdf.mainpdf(collection_name)
    client.close()

    # vulners_api = vulners.Vulners(api_key=os.getenv('API_KEY'))
    # print(get_vulnerability_description(vulners_api, ['CVE-2023-42115'])['CVE-2023-42115']['description'])
    # get_vulnerability_description(vulners_api, 'DD37154C-0B91-5F1A-B3A1-A20843A3B651')
    # nm = nmap.PortScanner()
    # nm.scan(hosts='45.67.229.226-227', arguments='-sS -p 1-65000 -sV --script vulners', sudo=True)
    # host_range = ['45.67.229.226', '34.246.169.176']
    # with Pool(processes=max_concurrent_scans) as pool:
    #     results = pool.map(run_nmap_scan, host_range)

    # with open("data.json", "w", encoding="utf-8") as filewrite:
    #     json.dump(nm.analyse_nmap_xml_scan(), filewrite, ensure_ascii=False, indent=4)
    
    # with open("data.json", 'r', encoding='utf-8') as fileread:
    #     data = json.load(fileread)

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