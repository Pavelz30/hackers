
from fpdf import FPDF
from matplotlib import pyplot as plt
from pymongo import MongoClient
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Image, PageBreak, Paragraph,  Spacer
from reportlab.lib.styles import getSampleStyleSheet


from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import matplotlib.pyplot as plt
import io


def create_chart(data):
    # Пример: количество открытых и закрытых портов
    states = {'open': 0, 'closed': 0, 'filtered': 0}

    for item in data:
        state = item.get('state', 'unknown')
        if state in states:
            states[state] += 1

    # Построение графика
    plt.figure(figsize=(6, 4))
    plt.bar(states.keys(), states.values(), color=['green', 'red', 'orange'])
    plt.title('Состояния портов')
    plt.xlabel('Состояние')
    plt.ylabel('Количество')

    # Сохранение графика в байтовый поток
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return buf

def create_ports_chart(data):
    ip_ports_count = {}

    for item in data:
        ip = item.get('ip', 'N/A')
        state = item.get('state', 'unknown')
        if state == 'open':
            if ip not in ip_ports_count:
                ip_ports_count[ip] = 0
            ip_ports_count[ip] += 1
    ip_ports_count = dict(sorted(ip_ports_count.items(), key=lambda item: item[1], reverse=True)[:10])

    plt.figure(figsize=(10, 6))
    bars = plt.bar(ip_ports_count.keys(), ip_ports_count.values(), color='green')
    plt.xticks(rotation=45, ha='right')
    plt.title('Количество открытых портов на IP адрес')
    plt.xlabel('IP адрес')
    plt.ylabel('Количество открытых портов')
    plt.tight_layout()

    # Добавляем цифры над столбцами
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.05, int(yval), ha='center', va='bottom')


    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    return buf

def create_vulnerability_pie_chart(data):
    levels = {
        'Информационный': 0,
        'Средний': 0,
        'Высокий': 0,
        'Критичный': 0
    }

    for item in data:
        script = item.get('script', None)
        if script:
            for cvei in script:
                cvss = float(cvei[1])
                if cvss <= 2.5:
                    levels['Информационный'] += 1
                elif 3.0 < cvss <= 6.0:
                    levels['Средний'] += 1
                elif 6.0 < cvss <= 8.5:
                    levels['Высокий'] += 1
                else:
                    levels['Критичный'] += 1

    # Создание круговой диаграммы
    labels = list(levels.keys())
    sizes = list(levels.values())
    colors = ['lightblue', 'yellow', 'orange', 'red']
    
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
    plt.title('Распределение уязвимостей по уровням критичности')
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    return buf


def fetch_data_from_mongo(collection_name):
    client = MongoClient('localhost', 27017)
    db = client['scans']
    collection = db[collection_name]
    documents = collection.find()
    data = list(documents)
    client.close()
    return data
pdfmetrics.registerFont(TTFont('DejaVu', '/home/pavel/hack/dejavu-fonts-ttf-2.37/ttf/DejaVuSans.ttf'))

def generate_pdf(data, chart_buffer, filename='scan_report.pdf'):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    custom_style = styles['Normal'].clone('CustomStyle')  # Клонируем существующий стиль
    custom_style.fontName = 'DejaVu'  # Укажите зарегистрированное имя шрифта
    custom_style.fontSize = 30  # Установите желаемый размер шрифта
    custom_style.textColor = colors.HexColor('#333333')  # Установите цвет текста, если нужно
    custom_style.alignment = 1

    # Создание центрального текста для страницы
    centered_text = Paragraph("Отчет о сканировании периметра", custom_style)
    elements.append(Spacer(1, 200))  # Добавление простоного пространства сверху
    elements.append(centered_text)
    elements.append(Spacer(1, 200)) 
    elements.append(PageBreak())

    lst_ips = set([ ip.get('ip', 'N/A') for ip in data])
    custom_style.fontSize = 16
    custom_style.leading = 20
    centered_text = Paragraph(f'Были просканированы следующие ip-адреса: {lst_ips}', custom_style)
    elements.append(centered_text)
    elements.append(Spacer(1, 20)) 
    # Добавление графика в PDF
    img = Image(chart_buffer, width=400, height=300)  # Устанавливаем размеры изображений
    elements.append(img)

    chart_buffer = create_ports_chart(data)
    img = Image(chart_buffer, width=450, height=300)
    elements.append(img)
    elements.append(PageBreak())
    
    chart_buffer = create_vulnerability_pie_chart(data)
    img = Image(chart_buffer, width=450, height=450)
    elements.append(img)
    elements.append(PageBreak())

    fixed_col_widths = [100, 150, 100, 100, 100, 150] 
    # Подготовка данных для таблицы
    columns = ['IP-адрес', 'Имя хоста', 'Сервис/Версия', 'Порт/Протокол', 'Протокол L7', 'Статус порта']
    table_data = [columns]

    for item in data:
        ip = item.get('ip', 'N/A')
        hostname = ', '.join(item.get('hostname', []))
        service_version = f"{item.get('product', 'N/A')}/{item.get('version', 'N/A')}"
        port_protocol = f"{item.get('port', 'N/A')}/{item.get('protocol', 'N/A')}"
        status = item.get('state', 'N/A')
        l7_protocol = item.get('name', 'N/A')

        row = [ip, hostname, service_version, port_protocol, l7_protocol, status]
        table_data.append(row)

    columns2 = ['CVE', 'Имя хоста', 'Сервис/Версия', 'Порт/Протокол', 'CVSS V2', 'Описание']
    table_data_2 = [columns2]
    for item in data:
        hostname = Paragraph(', '.join(item.get('hostname', [])))
        service_version = Paragraph(f"{item.get('product', 'N/A')}/{item.get('version', 'N/A')}")
        port_protocol = f"{item.get('port', 'N/A')}/{item.get('protocol', 'N/A')}"
        status = item.get('state', 'N/A')
        l7_protocol = item.get('name', 'N/A')
        script  = item.get('script', [])
        if script:
            for cvei in script:
                cve = cvei[0]
                cvss = cvei[1]
                description = cvei[3]
                if description:
                    description = Paragraph(cvei[3][:300] + '...')
                row = [cve, hostname, service_version, port_protocol, cvss, description]
                table_data_2.append(row)

    # Создание и стилизация таблицы
    table = Table(table_data)
    table2 = Table(table_data_2, colWidths=fixed_col_widths)

    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.white),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'DejaVu'),  # Используем зарегистрированный шрифт
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    table.setStyle(style)
    table2.setStyle(style)

    elements.append(table)
    elements.append(PageBreak()) 

    doc.pagesize = landscape(letter)
    elements.append(table2)
    # Построение документа PDF
    doc.build(elements)


def make_table(data):
    df = pd.DataFrame(data[1:])
    print(df)
    class PDF(FPDF):
        def header(self):
            self.add_font('DejaVu', '', '/home/pavel/hack/dejavu-fonts-ttf-2.37/ttf/DejaVuSans.ttf', uni=True)
            self.set_font('DejaVu', '', 21)
            self.cell(0, 10, 'Отчет о сканировании периметра', ln=True, align='C')
            pdf.ln()
    
    pdf = PDF()
    pdf.add_page(orientation="L")
    pdf.set_font('DejaVu', '', 12)
    col_widths = [40, 55, 65, 40, 30, 40]
    cols = ['IP-адресс', 'Имя хоста', 'Сервис/Версия', 'Порт/Протокол', 'Протокол l7', 'Статус порта']
    for col_index, col_name in enumerate(cols):
        pdf.cell(col_widths[col_index], 10, col_name, border=1, align='C')
    pdf.ln()
    for index, row in df.iterrows():
        pdf.cell(col_widths[0], 10, row['ip'], border=1, align='C')
        pdf.cell(col_widths[1], 10, ', '.join(row['hostname']), border=1, align='C')
        pdf.cell(col_widths[2], 10, str(row.get('product', "None")) + '/' + str(row.get('version', "None")), border=1, align='C')
        pdf.cell(col_widths[3], 10, str(row['port']) + "/" + str(row['protocol']), border=1, align='C')
        pdf.cell(col_widths[4], 10, row['name'], border=1, align='C')
        pdf.cell(col_widths[5], 10, row['state'], border=1, align='C')
        pdf.ln()

    pdf.output("port_scan_results.pdf")
    print("PDF created successfully.")


def mainpdf(collection_name):
    data = fetch_data_from_mongo(collection_name)
    chart_buffer = create_chart(data)
    generate_pdf(data,chart_buffer,'new_pdf.pdf')
    