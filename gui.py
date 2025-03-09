import tkinter as tk
import customtkinter as ctk
from tkinter import scrolledtext, messagebox
from scanner import XSSScanner
from theme import ThemeManager
import threading
import time
import psutil

class XSSScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Hook_XSS Pro")
        self.geometry("900x400")
        self.minsize(1000, 600)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._setup_ui()
        self._create_menu()
        self.scanner = None
        self.scan_thread = None
        self.scan_active = False
        self.start_time = None
        self.total_tests = 0
        self.vuln_count = 0
        ThemeManager.set_theme("dark")

    def _setup_ui(self):
        main_container = ctk.CTkFrame(self)
        main_container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        main_container.grid_rowconfigure(0, weight=1)
        main_container.grid_columnconfigure(1, weight=1)

        # Sidebar
        sidebar = ctk.CTkFrame(main_container, width=250)
        sidebar.grid(row=0, column=0, sticky="ns", padx=10, pady=10)
        self._build_sidebar(sidebar)

        # Main content
        content = ctk.CTkFrame(main_container)
        content.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        content.grid_rowconfigure(3, weight=1)
        content.grid_columnconfigure(0, weight=1)
        
        # Build components
        self._build_scan_controls(content)
        self._build_progress(content)
        self._build_results(content)
        self._build_logs(content)

    def _build_sidebar(self, parent):
        stats = ctk.CTkFrame(parent)
        stats.pack(pady=10, fill="x")
        ctk.CTkLabel(stats, text="📊 Live Stats", font=("Arial", 14, "bold")).pack()
        self.total_tests_label = ctk.CTkLabel(stats, text="Total Tests: 0")
        self.total_tests_label.pack()
        self.vuln_count_label = ctk.CTkLabel(stats, text="Vulnerabilities: 0")
        self.vuln_count_label.pack()
        self.time_elapsed_label = ctk.CTkLabel(stats, text="Time Elapsed: 00:00:00")
        self.time_elapsed_label.pack()

        system = ctk.CTkFrame(parent)
        system.pack(pady=10, fill="x")
        ctk.CTkLabel(system, text="💻 System", font=("Arial", 14, "bold")).pack()
        self.cpu_usage_label = ctk.CTkLabel(system, text="CPU: 0%")
        self.cpu_usage_label.pack()
        self.ram_usage_label = ctk.CTkLabel(system, text="RAM: 0%")
        self.ram_usage_label.pack()

        themes = ctk.CTkFrame(parent)
        themes.pack(pady=10, fill="x")
        ctk.CTkLabel(themes, text="🎨 Themes", font=("Arial", 14, "bold")).pack()
        ctk.CTkButton(themes, text="Dark", command=lambda: self._change_theme("dark")).pack(fill="x")
        ctk.CTkButton(themes, text="Light", command=lambda: self._change_theme("light")).pack(fill="x")
        ctk.CTkButton(themes, text="Matrix", command=lambda: self._change_theme("matrix")).pack(fill="x")

    def _build_scan_controls(self, parent):
        config = ctk.CTkFrame(parent)
        config.grid(row=0, column=0, sticky="ew", pady=10)
        config.grid_columnconfigure(0, weight=1)
        
        url_frame = ctk.CTkFrame(config)
        url_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(url_frame, text="🌐 Target URL:", font=("Arial", 12)).pack(side="left")
        self.url_entry = ctk.CTkEntry(url_frame, placeholder_text="https://example.com")
        self.url_entry.pack(side="left", expand=True, fill="x", padx=5)

        options = ctk.CTkFrame(config)
        options.pack(fill="x", pady=5)
        
        payload_frame = ctk.CTkFrame(options)
        payload_frame.pack(side="left", padx=10)
        ctk.CTkLabel(payload_frame, text="📦 Payload Mode:").pack()
        self.payload_mode = ctk.StringVar(value="default")
        ctk.CTkRadioButton(payload_frame, text="Default", variable=self.payload_mode, value="default").pack(anchor="w")
        ctk.CTkRadioButton(payload_frame, text="Pro (GitHub)", variable=self.payload_mode, value="pro").pack(anchor="w")

        method_frame = ctk.CTkFrame(options)
        method_frame.pack(side="left", padx=10)
        ctk.CTkLabel(method_frame, text="📡 HTTP Method:").pack()
        self.method_var = ctk.StringVar(value="both")
        ctk.CTkRadioButton(method_frame, text="GET", variable=self.method_var, value="get").pack(anchor="w")
        ctk.CTkRadioButton(method_frame, text="POST", variable=self.method_var, value="post").pack(anchor="w")
        ctk.CTkRadioButton(method_frame, text="Both", variable=self.method_var, value="both").pack(anchor="w")

        controls = ctk.CTkFrame(config)
        controls.pack(fill="x", pady=5)
        self.start_btn = ctk.CTkButton(
            controls,
            text="▶ Start Scan",
            font=("Arial", 14, "bold"),
            command=self.start_scan
        )
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = ctk.CTkButton(
            controls,
            text="⏹ Stop Scan",
            font=("Arial", 14, "bold"),
            state="disabled",
            command=self.stop_scan
        )
        self.stop_btn.pack(side="left", padx=5)

    def _build_progress(self, parent):
        progress = ctk.CTkFrame(parent)
        progress.grid(row=1, column=0, sticky="ew", pady=10)
        progress.grid_columnconfigure(0, weight=1)
        
        self.progress_bar = ctk.CTkProgressBar(progress, height=20)
        self.progress_bar.pack(fill="x", expand=True)
        
        labels = ctk.CTkFrame(progress)
        labels.pack(fill="x")
        self.progress_label = ctk.CTkLabel(labels, text="Progress: 0%")
        self.progress_label.pack(side="left")
        self.time_remaining_label = ctk.CTkLabel(labels, text="Estimated: --:--")
        self.time_remaining_label.pack(side="right")

    def _build_results(self, parent):
        tabs = ctk.CTkTabview(parent)
        tabs.grid(row=2, column=0, sticky="nsew", pady=10)
        tabs.grid_rowconfigure(0, weight=1)
        tabs.grid_columnconfigure(0, weight=1)
        
        self.live_tab = tabs.add("🔴 Live Results")
        self.live_list = ctk.CTkScrollableFrame(self.live_tab)
        self.live_list.pack(fill="both", expand=True)
        
        self.report_tab = tabs.add("📄 Final Report")
        self.report_area = scrolledtext.ScrolledText(
            self.report_tab,
            wrap=tk.WORD,
            font=("Consolas", 12)
        )
        self.report_area.pack(fill="both", expand=True)
        self.report_area.config(state="disabled")

    def _build_logs(self, parent):
        log_frame = ctk.CTkFrame(parent)
        log_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        
        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 12)
        )
        self.log_area.pack(fill="both", expand=True)
        self.log_area.tag_config("INFO", foreground="#17a2b8")
        self.log_area.tag_config("SUCCESS", foreground="#28a745")
        self.log_area.tag_config("ERROR", foreground="#dc3545")
        self.log_area.config(state="disabled")

    def _create_menu(self):
        menu_bar = tk.Menu(self)
        
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        
        menu_bar.add_cascade(label="File", menu=file_menu)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.config(menu=menu_bar)

    def _change_theme(self, theme_name):
        try:
            ThemeManager.set_theme(theme_name)
            self._update_theme_colors()
            self.log(f"Theme changed to {theme_name.capitalize()}", "INFO")
        except Exception as e:
            self.log(f"Theme error: {str(e)}", "ERROR")

    def _update_theme_colors(self):
        theme = ctk.ThemeManager.theme
        self.progress_bar.configure(
            fg_color=theme["CTkProgressBar"]["fg_color"],
            progress_color=theme["CTkProgressBar"]["progress_color"]
        )

    def start_scan(self):
        if self.scan_active:
            return

        url = self.url_entry.get().strip()
        if not url:
            self.log("Please enter a valid URL", "ERROR")
            return

        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        self.scanner = XSSScanner(
            callback=self.handle_scan_event,
            payload_type=self.payload_mode.get(),
            max_depth=2,
            max_threads=10
        )
        
        self.scan_active = True
        self.start_time = time.time()
        self.total_tests = 0
        self.vuln_count = 0
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress_bar.set(0)
        
        # Clear previous results
        for widget in self.live_list.winfo_children():
            widget.destroy()
        self.report_area.config(state="normal")
        self.report_area.delete(1.0, tk.END)
        self.report_area.config(state="disabled")
        self.log_area.config(state="normal")
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state="disabled")

        self.scan_thread = threading.Thread(target=self._scan_worker, args=(url,), daemon=True)
        self.scan_thread.start()
        self.after(100, self._monitor_scan)

    def _scan_worker(self, url):
        try:
            vulnerabilities = self.scanner.scan(url)
            self.log(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities", "SUCCESS")
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
        finally:
            self.scan_active = False

    def _monitor_scan(self):
        if self.scan_active:
            self._update_stats()
            self._update_system_stats()
            self.after(1000, self._monitor_scan)
        else:
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")

    def stop_scan(self):
        if self.scanner:
            self.scanner.scan_active = False
        self.scan_active = False
        self.log("Scan stopped by user", "INFO")

    def _update_stats(self):
        elapsed = time.time() - self.start_time
        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)
        self.time_elapsed_label.configure(text=f"Time Elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}")
        self.total_tests_label.configure(text=f"Total Tests: {self.total_tests}")
        self.vuln_count_label.configure(text=f"Vulnerabilities: {self.vuln_count}")

    def _update_system_stats(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.cpu_usage_label.configure(text=f"CPU: {cpu}%")
        self.ram_usage_label.configure(text=f"RAM: {ram}%")

    def handle_scan_event(self, event):
        event_type = event.get('type')
        if event_type == 'PROGRESS':
            current = event['current']
            total = event['total']
            self.progress_bar.set(current / total)
            self.progress_label.configure(text=f"Progress: {current/total*100:.1f}%")
            self.total_tests = current
        elif event_type == 'VULNERABILITY':
            self._add_vulnerability(event)
            self.vuln_count += 1
        elif event_type in ['INFO', 'SUCCESS', 'ERROR']:
            self.log(event['message'], event_type)

    def _add_vulnerability(self, vuln):
        frame = ctk.CTkFrame(self.live_list)
        frame.pack(fill="x", pady=2)
        ctk.CTkLabel(frame, text=vuln['type'], width=100).pack(side="left")
        ctk.CTkLabel(frame, text=vuln['url'], width=400).pack(side="left")
        ctk.CTkLabel(frame, text=vuln['payload'], width=300).pack(side="left")
        
        self.report_area.config(state="normal")
        self.report_area.insert("end", 
            f"[+] {vuln['type']} Vulnerability Found!\n"
            f"URL: {vuln['url']}\n"
            f"Payload: {vuln['payload']}\n"
            "--------------------------------------------------\n"
        )
        self.report_area.see("end")
        self.report_area.config(state="disabled")

    def log(self, message, level="INFO"):
        self.log_area.config(state="normal")
        self.log_area.insert("end", f"[{level}] {message}\n", level)
        self.log_area.see("end")
        self.log_area.config(state="disabled")

    def export_report(self):
        messagebox.showinfo("Info", "Export feature coming soon!")

    def show_docs(self):
        messagebox.showinfo("Documentation", "Visit: https://docs.xss.com")

    def show_about(self):
        messagebox.showinfo("About", 
            "Hook_XSS Pro v3.0\n"
            "Advanced XSS Vulnerability Scanner\n"
            "Developed by Security Experts Team (Eric.Pd) (Liam.Pd)\n"
            "© 2024 All rights reserved"
        )

if __name__ == "__main__":
    app = XSSScannerGUI()
    app.mainloop()