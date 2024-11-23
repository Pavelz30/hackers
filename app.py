import nmap
import json
import pprint
import requests
import vulners
import os
from fpdf import FPDF
import translator


def get_vulnerability_description(vulners_api: vulners, vulnerability_ids):
    return vulners_api.get_multiple_bulletins(id=vulnerability_ids, fields=["description"])

    
def main():

    vulners_api = vulners.Vulners(api_key=os.getenv('API_KEY'))

    nm = nmap.PortScanner()
    nm.scan(hosts='45.67.229.226', arguments='-sS -F -sV --script vulners', sudo=True)
    
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
    # data = json.loads(json_data)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)

    pdf.cell(200, 10, txt="Отчет о тетсировании", ln=True, align='C')
    pdf.ln(10)
    for proto in nm.scaninfo():
        ports = nm.scaninfo()[proto]['services']
        pdf.cell(200, 10, txt=ports, ln=True, align='C')
    # # Добавляем пространство
    # pdf.ln(10)

    # def add_row(row_data):
    #     for item in row_data:
    #         pdf.cell(40, 10, txt=item, border=1)
    #     pdf.ln()

    # # Печать заголовка таблицы
    # add_row(data['header'])

    # # Печать данных
    # for row in data['data']:
    #     add_row([row['ID'], row['Name'], row['Value']])

    # Сохраняем PDF
    pdf_output_path = "output.pdf"
    pdf.output(pdf_output_path)
    print(f"PDF успешно создан: {pdf_output_path}")


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