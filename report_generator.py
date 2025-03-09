from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import csv
from datetime import datetime

class ReportGenerator:
    def __init__(self, vulnerabilities):
        self.vulns = vulnerabilities
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_pdf(self):
        filename = f"reports/report_{self.timestamp}.pdf"
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4
        
        # Header
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height-50, "Hook_XSS Pro Scan Report")
        
        # Content
        y = height - 80
        c.setFont("Helvetica", 12)
        for vuln in self.vulns:
            text = f"[{vuln['type']}] {vuln['url']}"
            c.drawString(50, y, text)
            c.drawString(70, y-15, f"Payload: {vuln['payload']}")
            y -= 30
            if y < 100:
                c.showPage()
                y = height - 50
        
        c.save()
        return filename
    
    def generate_csv(self):
        filename = f"reports/report_{self.timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "URL", "Payload"])
            for vuln in self.vulns:
                writer.writerow([vuln['type'], vuln['url'], vuln['payload']])
        return filename