from bs4 import BeautifulSoup

class CSRFTester:
    def __init__(self, html_content):
        self.soup = BeautifulSoup(html_content, 'html.parser')
    
    def check_protection(self):
        forms = self.soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                return False
        return True