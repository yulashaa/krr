import os
import subprocess
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import logging
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

logging.basicConfig(filename='access_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    return encrypted_file_path

is_logging = False
event_list = []
entry_password = None
folder_monitor_thread = None
printer_monitor_thread = None
selected_registry_key = None
folder_path = None
printer_name = None
encryption_key = generate_key()

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        log_event(f'Файл створено: {os.path.basename(event.src_path)} у {folder_path}')
        check_user_access(event.src_path)

    def on_deleted(self, event):
        log_event(f'Файл видалено: {os.path.basename(event.src_path)} з {folder_path}')

    def on_modified(self, event):
        log_event(f'Файл змінено: {os.path.basename(event.src_path)} у {folder_path}')

    def on_moved(self, event):
        log_event(f'Файл переміщено: {os.path.basename(event.src_path)} з {folder_path}')

def log_event(event):
    global event_list
    event_list.append(event)
    logging.info(event)
    display_events()

def check_user_access(path):
    try:
        users = subprocess.check_output(["who"]).decode().strip().split('\n')
        for user in users:
            log_event(f'Користувач {user} отримав доступ до: {path}')
    except Exception as e:
        log_event(f'Помилка при перевірці доступу користувачів: {str(e)}')

def start_logging():
    global is_logging, folder_monitor_thread, printer_monitor_thread
    is_logging = True
    log_event("Початок протоколювання")

    if folder_path:
        folder_monitor_thread = threading.Thread(target=monitor_folder)
        folder_monitor_thread.start()

    if printer_name:
        printer_monitor_thread = threading.Thread(target=monitor_printer)
        printer_monitor_thread.start()

def stop_logging():
    global is_logging
    is_logging = False
    log_event("Закінчення протоколювання")
    messagebox.showinfo("Log", "Протоколювання завершено.")

def monitor_folder():
    global folder_path
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=True)
    observer.start()

    try:
        while is_logging:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.stop()
    observer.join()

def monitor_printer():
    global printer_name
    while is_logging:
        try:
            output = subprocess.check_output(["lpstat", "-p"])
            if printer_name not in output.decode():
                log_event(f'Принтер {printer_name} не доступний.')
            else:
                log_event(f'Принтер {printer_name} доступний.')
        except Exception as e:
            log_event(f'Помилка при перевірці принтера {printer_name}: {str(e)}')
        time.sleep(5)

def monitor_registry():
    global selected_registry_key
    while is_logging:
        log_event(f'Доступ до розділу реєстру: {selected_registry_key}')
        time.sleep(5)

def display_events():
    events_text.delete(1.0, tk.END)
    for event in event_list:
        events_text.insert(tk.END, event + '\n')

def on_select_folder():
    global folder_path
    folder_path = filedialog.askdirectory()
    if folder_path:
        log_event(f'Обрана папка: {folder_path}')

def get_printer_list():
    try:
        output = subprocess.check_output(["lpstat", "-p"]).decode().strip().split('\n')
        printers = [line.split()[1] for line in output if line]
        return printers
    except Exception as e:
        log_event(f'Помилка при отриманні списку принтерів: {str(e)}')
        return []

def on_select_printer(selected_printer):
    global printer_name
    printer_name = selected_printer
    log_event(f'Обрано принтер: {printer_name}')

def on_select_registry():
    global selected_registry_key
    registry_key = simpledialog.askstring("Вибір розділу реєстру", "Введіть шлях до розділу реєстру:")
    if registry_key:
        selected_registry_key = registry_key
        log_event(f'Обрано розділ реєстру: {registry_key}')

def validate_admin_password():
    password = entry_password.get()
    if password == "admincheck23":
        main_window()
    else:
        messagebox.showerror("Error", "Неправильний пароль!")

def password_window():
    pw_window = tk.Toplevel()
    pw_window.title("Пароль адміністратора")
    tk.Label(pw_window, text="Введіть пароль адміністратора:").pack()
    global entry_password
    entry_password = tk.Entry(pw_window, show="*")
    entry_password.pack()

    tk.Button(pw_window, text="Підтвердити", command=validate_admin_password).pack()

def download_encrypted_logs():
    log_file_path = 'access_log.txt'
    if os.path.exists(log_file_path):
        encrypted_file_path = encrypt_file(log_file_path, encryption_key)
        messagebox.showinfo("Download", f"Логи зашифровані та збережені як: {encrypted_file_path}")
    else:
        messagebox.showerror("Error", "Файл логів не знайдено!")

def main_window():
    global root, events_text, printer_var

    for widget in root.winfo_children():
        widget.destroy()

    tk.Button(root, text="Оберіть папку", command=on_select_folder).pack(pady=15)

    tk.Label(root, text="Оберіть принтер:").pack()
    printer_var = tk.StringVar(root)
    printer_list = get_printer_list()
    if printer_list:
        printer_var.set(printer_list[0])
    printer_dropdown = tk.OptionMenu(root, printer_var, *printer_list, command=on_select_printer)
    printer_dropdown.pack()
    
    tk.Button(root, text="Оберіть розділ реєстру", command=on_select_registry).pack(pady=15)

    tk.Button(root, text="Почати протоколювання", command=start_logging).pack()
    tk.Button(root, text="Закінчити протоколювання", command=stop_logging).pack()
    tk.Button(root, text="Завантажити логи", command=download_encrypted_logs).pack()

    events_text = tk.Text(root, height=30, width=60)
    events_text.pack(pady=10)

def create_password_window():
    global root
    root = tk.Tk()
    root.title("Access Monitoring System")
    password_window()

create_password_window()
root.mainloop()