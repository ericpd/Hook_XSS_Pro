import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import threading

class XSSScanner:
    def __init__(self, callback=None, payload_type='default', max_depth=2, max_threads=10):
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Hook_XSS Pro/2.1'}
        self.found_vulns = []
        self.scan_active = False
        self.callback = callback
        self.payloads = self._load_payloads(payload_type)
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.total_payloads = len(self.payloads)
        self.tested_count = 0

    def _load_payloads(self, payload_type):
        if payload_type == 'pro':
            return self._load_github_payloads()
        else:
            return [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '"><script>alert(1)</script>',
                'javascript:alert(1)',
                '<svg onload=alert(1)>'
            ]
    
    def _load_github_payloads(self):
        try:
            url = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return [p.strip() for p in response.text.splitlines() if p.strip()]
            return self._load_payloads('default')
        except:
            return self._load_payloads('default')

    def scan(self, start_url):
        self.scan_active = True
        visited = set()
        queue = [(start_url, 0)]
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while queue and self.scan_active:
                current_url, depth = queue.pop(0)
                if depth > self.max_depth or current_url in visited:
                    continue
                
                visited.add(current_url)
                self._notify(f"Scanning: {current_url}", "INFO")

                try:
                    crawled_data = self._crawl(current_url)
                    
                    # Submit all test tasks
                    futures = []
                    futures.append(executor.submit(self._test_url, current_url))
                    for form in crawled_data['forms']:
                        futures.append(executor.submit(self._test_form, form))
                    
                    # Process results as they complete
                    for future in futures:
                        results = future.result()
                        for result in results:
                            self.found_vulns.append(result)
                            self._notify(result, "VULNERABILITY")
                    
                    # Add new links to queue
                    queue.extend((link, depth+1) for link in crawled_data['links'] if link not in visited)
                
                except Exception as e:
                    self._notify(f"Scan Error: {str(e)}", "ERROR")
        
        self.scan_active = False
        return self.found_vulns

    def _crawl(self, url):
        try:
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            return {
                'links': [urljoin(url, a['href']) for a in soup.find_all('a', href=True)],
                'forms': self._parse_forms(soup, url)
            }
        except Exception as e:
            self._notify(f"Crawling Error: {str(e)}", "ERROR")
            return {'links': [], 'forms': []}

    def _parse_forms(self, soup, base_url):
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', base_url)
            method = form.get('method', 'get').lower()
            inputs = []
            
            for tag in form.find_all(['input', 'textarea']):
                name = tag.get('name')
                if name:
                    inputs.append({
                        'name': name,
                        'type': tag.get('type', 'text'),
                        'value': tag.get('value', '')
                    })
            
            forms.append({
                'action': urljoin(base_url, action),
                'method': method,
                'inputs': inputs
            })
        return forms

    def _test_url(self, url):
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in self.payloads:
                if not self.scan_active:
                    return results
                
                test_params = {k: payload if k == param else v[0] for k, v in params.items()}
                test_url = parsed._replace(query="&".join(f"{k}={v}" for k, v in test_params.items())).geturl()
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    self._update_progress()
                    if payload in response.text:
                        results.append({
                            'type': 'URL',
                            'url': test_url,
                            'payload': payload
                        })
                except:
                    continue
        return results

    def _test_form(self, form):
        results = []
        for payload in self.payloads:
            if not self.scan_active:
                return results
            
            try:
                data = {}
                for field in form['inputs']:
                    data[field['name']] = payload if field['type'] != 'hidden' else field['value']
                
                if form['method'] == 'post':
                    response = self.session.post(form['action'], data=data, timeout=10)
                else:
                    response = self.session.get(form['action'], params=data, timeout=10)
                
                self._update_progress()
                if payload in response.text:
                    results.append({
                        'type': 'FORM',
                        'url': form['action'],
                        'payload': payload
                    })
            except:
                continue
        return results

    def _update_progress(self):
        self.tested_count += 1
        if self.callback:
            self.callback({
                'type': 'PROGRESS',
                'current': self.tested_count,
                'total': self.total_payloads * 2  # For both URL and form tests
            })

    def _notify(self, message, level):
        if self.callback:
            self.callback({
                'type': level,
                'message': message
            })