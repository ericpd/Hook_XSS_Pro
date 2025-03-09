import os
import customtkinter as ctk

class ThemeManager:
    THEME_FILES = {
        "dark": os.path.join(os.path.dirname(__file__), "themes", "dark.json"),
        "light": os.path.join(os.path.dirname(__file__), "themes", "light.json"),
        "matrix": os.path.join(os.path.dirname(__file__), "themes", "matrix.json")
    }

    @classmethod
    def set_theme(cls, theme_name):
        theme_name = theme_name.lower()
        theme_path = cls.THEME_FILES.get(theme_name)
        if not theme_path or not os.path.exists(theme_path):
            raise ValueError(f"Theme '{theme_name}' not found")
        
        ctk.set_appearance_mode("dark" if theme_name in ["dark", "matrix"] else "light")
        ctk.set_default_color_theme(theme_path)