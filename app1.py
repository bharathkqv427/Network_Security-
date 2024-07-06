
from flask import Flask, request, send_file, render_template
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, inch
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os
import hashlib
import random
import textwrap
from datetime import datetime
from PyPDF4 import PdfFileReader, PdfFileWriter

app = Flask(__name__)

students = [
    {"name": "Vansh", "roll": "2021363", "dob": "2002-01-01", "password": "0b6b4634865306891dc18704583a08aceb6ece0a50fdf3e6484d83ddf3dceb62"}, #vanshhh
    {"name": "V Bharath", "roll": "2021362", "dob": "2003-08-09", "password": "a5515368ffb39ce1f6fa7670740d5bd345c998b43813aecf3f5c58828e54e85f"}, #bharath
]

def generate_watermark(roll, suffix):
    wt = f"Issued to {roll} on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC by IIITD University"
    waterfile = f"watermark_{suffix}.pdf"
    WC = canvas.Canvas(waterfile, pagesize=letter)
    WC.setFont('Helvetica-Bold', 15)
    WC.setFillColorRGB(0.49, 0.51, 0.52, 0.2)
    WC.rotate(45)
    text_width = WC.stringWidth(wt)
    x = -6.5 * inch
    y = (1-0.5) * inch
    while x < 8.25 * inch:
        WC.drawString(x, y, wt)
        x += text_width + 20
    WC.save()
    return waterfile

def MERGEWWATR(doc_name, waterfile):
    inputp = PdfFileReader(open(doc_name, "rb"))
    wpdf = PdfFileReader(open(waterfile, "rb"))
    output = PdfFileWriter()
    for i in range(inputp.getNumPages()):
        page = inputp.getPage(i)
        page.mergePage(wpdf.getPage(0))
        output.addPage(page)
    merged_file = f"merged_{doc_name}"
    with open(merged_file, "wb") as outputStream:
        output.write(outputStream)
    return merged_file

def GD(name, roll, suffix, pkey_registrar, pkey_director):
    doc_name = f"{name}_{suffix}.pdf"
    pdf = canvas.Canvas(doc_name, pagesize=letter)
    pdf.drawString(100, 750, f"Name: {name.title()}")
    pdf.drawString(100, 700, f"Roll: {roll}")
    pdf.drawString(100, 650, f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC")
    pdata = pdf.getpdfdata()
    pdf_hash = hashlib.sha256(pdata).digest()
    sig_registrar = pkey_registrar.sign(pdf_hash, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    sig_director = pkey_director.sign(pdf_hash, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    sig_text = f"Registrar: {sig_registrar.hex()} Director: {sig_director.hex()}"
    lines = textwrap.wrap(sig_text, width=50)
    y_offset = 550
    for line in lines:
        pdf.drawString(100, y_offset, line)
        y_offset -= 15
    pdf.save()
    
    waterfile = generate_watermark(roll, suffix)
    merged_file = MERGEWWATR(doc_name, waterfile)
    os.remove(waterfile)
    
    return sig_registrar, sig_director, pdf_hash, merged_file

def verifysig(signature, message_hash, public_key):
    try:
        public_key.verify(signature, message_hash, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def get_graduate_info():
    name, roll, dob, password = request.form['graduate_name'], request.form['roll_number'], request.form['dob'], request.form['hashed_password']
    print(f"Received data: Name: {name}, Roll: {roll}, DOB: {dob}, Password: {password}")  # Print received data
    for student in students:
        if student["name"].lower() == name.lower() and student["roll"] == roll and student["dob"] == dob:
            if student["password"] == password:
                pkey_registrar, pkey_director = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
                sig_registrar, sig_director, pdf_hash, merged_file = GD(name, roll, "certificate", pkey_registrar, pkey_director)
                sig_registrar_grade, sig_director_grade, pdf_hash_grade, merged_file_grade = GD(name, roll, "gradecard", pkey_registrar, pkey_director)
                verified_registrar = verifysig(sig_registrar, pdf_hash, pkey_registrar.public_key())
                verified_director = verifysig(sig_director, pdf_hash, pkey_director.public_key())
                if verified_registrar and verified_director:
                    print("Both digital signatures verified.")
                    return render_template('download_files.html', degree_name=merged_file, grade_name=merged_file_grade)
                else:
                    print("Digital signatures verification failed.")
            else:
                return "Authentication Failed: Incorrect Password"
    return "Authentication Failed: Student information not found"

@app.route('/download/<filename>', methods=['GET'])
def download_pdf(filename):
    file_path = f"{filename}"
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "Error: File not found"

if __name__ == '__main__':
    app.run()
