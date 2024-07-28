import os
import time
import psutil
import tkinter as tk
from tkinter import ttk, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

class LogHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            self.app.log_files.append(event.src_path)
            self.app.log_event(f"Fichier journal détecté : {event.src_path}")

    def __init__(self, app):
        self.app = app

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("LogsRemover made by cia #branchezvous")
        self.root.geometry("800x600")  

        self.toolbar = tk.Frame(self.root)
        self.toolbar.pack(side='top', fill='x')


        self.refresh_button = ttk.Button(self.toolbar, text="Actualiser", command=self.update_process_list)
        self.refresh_button.pack(side='left', padx=5, pady=5)


        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.auto_refresh_check = ttk.Checkbutton(self.toolbar, text="Actualisation automatique", variable=self.auto_refresh_var)
        self.auto_refresh_check.pack(side='left', padx=5, pady=5)


        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state=tk.DISABLED)
        self.text_area.pack(expand=True, fill='both')


        self.process_list = ttk.Treeview(self.root, columns=('pid', 'status'))
        self.process_list.pack(expand=True, fill='both')
        self.process_list.heading("#0", text="Processus")
        self.process_list.heading("pid", text="PID")
        self.process_list.heading("status", text="Statut")

        self.process_list.column("#0", width=400)
        self.process_list.column("pid", width=100)
        self.process_list.column("status", width=200)

        self.process_list.bind("<Button-3>", self.show_context_menu)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Fermer le processus et supprimer les journaux", command=self.terminate_process)

        self.running_exes = {}
        self.detected_exes = set()
        self.log_files = []
        self.existing_pids = {p.pid for p in psutil.process_iter(['pid'])}

        self.start_log_monitoring()
        self.start_exe_monitoring()

    def log_event(self, message):
        self.text_area.configure(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.yview(tk.END)

        self.text_area.configure(state=tk.DISABLED)

    def start_log_monitoring(self):
        dir_to_monitor = r'D:\\' 
        event_handler = LogHandler(self)
        observer = Observer()
        observer.schedule(event_handler, path=dir_to_monitor, recursive=True)
        observer.start()
        threading.Thread(target=self._keep_observer_running, args=(observer,), daemon=True).start()

    def _keep_observer_running(self, observer):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def start_exe_monitoring(self):
        threading.Thread(target=self._monitor_executables, daemon=True).start()

    def _monitor_executables(self):
        while True:
            current_exes = {p.info['pid']: (p.info['name'], p.info['exe']) for p in psutil.process_iter(['pid', 'name', 'exe']) if p.info['pid'] not in self.existing_pids and p.info['name'].endswith('.exe') and 'system32' not in p.info['exe'].lower()}
            for pid, (name, path) in current_exes.items():
                if (name, path) not in self.detected_exes:
                    self.running_exes[pid] = (name, path)
                    self.detected_exes.add((name, path))
                    self.log_event(f"Nouvel .exe détecté : {name} ({path})")
            if self.auto_refresh_var.get():
                self.update_process_list()
            time.sleep(1)

    def update_process_list(self, *args):
        for item in self.process_list.get_children():
            self.process_list.delete(item)
        for pid, (name, path) in self.running_exes.items():
            try:
                proc = psutil.Process(pid)
                if proc.is_running():
                    status = "En cours d'exécution"
                else:
                    status = "Arrêté"
            except psutil.NoSuchProcess:
                status = "Introuvable"

            display_name = name
            if list(self.running_exes.values()).count((name, path)) > 1:
                display_name = f"{name} ({path})"
            self.process_list.insert("", "end", iid=pid, text=display_name, values=(pid, status))

    def show_context_menu(self, event):
        item = self.process_list.identify_row(event.y)
        if item:
            self.process_list.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def terminate_process(self):
        selected_items = self.process_list.selection()
        if not selected_items:
            self.log_event("Aucun processus sélectionné.")
            return
        for selected_item in selected_items:
            pid = int(selected_item)
            process_name, process_path = self.running_exes.get(pid, (None, None))
            if process_name:
                try:
                    proc = psutil.Process(pid)
                    if proc.is_running():
                        for child in proc.children(recursive=True):
                            child.terminate()
                        proc.terminate()
                        proc.wait(timeout=3)
                    if not proc.is_running():
                        del self.running_exes[pid]
                        self.process_list.delete(selected_item)
                        self.log_event(f"Processus {process_name} (PID: {pid}) terminé.")
                    else:
                        self.log_event(f"Erreur : Le processus {process_name} (PID: {pid}) est toujours en cours d'exécution.")
                except psutil.NoSuchProcess:
                    self.log_event(f"Erreur lors de la fermeture du processus {process_name} (PID: {pid}): processus introuvable.")
                except Exception as e:
                    self.log_event(f"Erreur lors de la fermeture du processus {process_name} (PID: {pid}): {str(e)}")
        self.clear_logs()

    def clear_logs(self):
        for log_file in self.log_files:
            if os.path.exists(log_file):
                try:
                    os.remove(log_file)
                    self.log_event(f"Fichier journal supprimé : {log_file}")
                except Exception as e:
                    self.log_event(f"Erreur lors de la suppression du fichier journal {log_file}: {str(e)}")
            else:
                self.log_event(f"Fichier journal non trouvé : {log_file}")
        self.log_files.clear()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
