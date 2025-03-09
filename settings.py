import json
import os

class Settings:
    def __init__(self):
        self.config_file = "hook_xss_config.json"
        self.defaults = {
            "theme": "dark",
            "max_depth": 2,
            "threads": 10,
            "recent_urls": []
        }
        self.config = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return {**self.defaults, **json.load(f)}
            except:
                return self.defaults
        return self.defaults
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)