from fpdf import FPDF
from pymongo import MongoClient
import pandas as pd



# title = 'Отчет о сканировании внешнего периметра'

# class PDF(FPDF):
#     def header(self):
#         self.set_font('Arial', 'B', 15)
#         w = self.get_string_width(title) + 6
#         self.set_x((210 - w) / 2)
#         self.set_draw_color(0, 80, 180)
#         self.set_fill_color(230, 230, 0)
#         self.set_text_color(220, 50, 50)
#         self.set_line_width(1)
#         self.cell(w, 9, title, 1, 1, 'C', 1)
#         self.ln(10)

#     def footer(self):
#         self.set_y(-15)
#         self.set_font('Arial', 'I', 8)
#         self.set_text_color(128)
#         self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')

#     def chapter_title(self, num, label):
#         self.set_font('Arial', '', 12)
#         self.set_fill_color(200, 220, 255)
#         self.cell(0, 6, 'Chapter %d : %s' % (num, label), 0, 1, 'L', 1)
#         self.ln(4)

#     def chapter_body(self, name):
#         with open(name, 'rb') as fh:
#             txt = fh.read().decode('latin-1')
#         self.set_font('Times', '', 12)
#         self.multi_cell(0, 5, txt)
#         self.ln()
#         self.set_font('', 'I')
#         self.cell(0, 5, '(end of excerpt)')

#     def print_chapter(self, num, title, name):
#         self.add_page()
#         self.chapter_title(num, title)
#         self.chapter_body(name)


def fetch_data_from_mongo(collection_name):
    client = MongoClient('localhost', 27017)
    db = client['scans']
    collection = db[collection_name]
    documents = collection.find()
    data = list(documents)
    client.close()
    return data

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
        # pdf.cell(col_widths[0], 10, row['ip'], border=1, align='C')
        # pdf.multi_cell(col_widths[1], 10, ', '.join(row['hostname']), border=1, align='C')
        # pdf.multi_cell(col_widths[2], 10, str(row.get('product', "None")) + '/' + str(row.get('version', "None")), border=1, align='C')
        # pdf.cell(col_widths[3], 10, str(row['port']) + "/" + str(row['protocol']), border=1, align='C')
        # pdf.cell(col_widths[4], 10, row['name'], border=1, align='C')
        # pdf.cell(col_widths[5], 10, row['state'], border=1, align='C')
        # pdf.ln()
        max_height = 10
        x_start = pdf.get_x()
        y_start = pdf.get_y()
        
        pdf.cell(col_widths[0], max_height, row['ip'], border=1, align='C')

        pdf.set_xy(x_start + col_widths[0], y_start)
        hostname_text = ', '.join(row['hostname'])
        pdf.multi_cell(col_widths[1], 10, hostname_text, border=1, align='C')
        max_height = max(max_height, pdf.get_y() - y_start)

        pdf.set_xy(x_start + col_widths[0] + col_widths[1], y_start)
        product_text = str(row.get('product', "None")) + '/' + str(row.get('version', "None"))
        pdf.multi_cell(col_widths[2], 10, product_text, border=1, align='C')
        max_height = max(max_height, pdf.get_y() - y_start)

        pdf.set_xy(x_start + col_widths[0] + col_widths[1] + col_widths[2], y_start)
        port_text = str(row['port']) + "/" + str(row['protocol'])
        pdf.cell(col_widths[3], max_height, port_text, border=1, align='C')

        pdf.set_xy(x_start + col_widths[0] + col_widths[1] + col_widths[2] + col_widths[3], y_start)
        pdf.cell(col_widths[4], max_height, row['name'], border=1, align='C')

        pdf.set_xy(x_start + col_widths[0] + col_widths[1] + col_widths[2] + col_widths[3] + col_widths[4], y_start)
        pdf.cell(col_widths[5], max_height, row['state'], border=1, align='C')

        pdf.set_y(y_start + max_height)



    pdf.output("port_scan_results.pdf")
    print("PDF created successfully.")


def mainpdf(collection_name):
    data = fetch_data_from_mongo(collection_name)
    make_table(data)