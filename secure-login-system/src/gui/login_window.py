import time
from gui.admin_view import AdminView
from gui.collaborator_view import CollaboratorView
from tkinter import Frame, Tk, Label, Entry, Button, StringVar, messagebox
from persistence.user_repository import get_user_by_username
from utils.password_utils import verify_password
from persistence.base_datos import SessionLocal

class LoginWindow(Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.title("Login")
        self.master.geometry("300x200")

        self.username_var = StringVar()
        self.password_var = StringVar()
        self.attempts = 0
        self.locked = False
        self.lock_time = None

        Label(master, text="Username").pack(pady=10)
        Entry(master, textvariable=self.username_var).pack()

        Label(master, text="Password").pack(pady=10)
        Entry(master, textvariable=self.password_var, show='*').pack()

        Button(master, text="Login", command=self.login).pack(pady=20)
        Button(master, text="Salir", command=self.master.quit).pack(pady=5)  # Botón para cerrar la app
        
        Button(master, text="Login", command=self.login).pack(pady=20)

    def login(self):
        if self.locked:
            remaining_time = 300 - (time.time() - self.lock_time)  # 5 minutos
            if remaining_time > 0:
                mins = int(remaining_time // 60)
                secs = int(remaining_time % 60)
                messagebox.showerror(
                    "Account Locked", 
                    f"Too many failed attempts. Try again in {mins}m {secs}s"
                )
                return
            else:
                self.locked = False
                self.attempts = 0

        username = self.username_var.get()
        password = self.password_var.get()
        with SessionLocal() as db:
            user = get_user_by_username(db, username)
            if user and verify_password(password, user.password):
                self.attempts = 0  # Reset attempts on successful login
                self.master.withdraw()
                if user.role == 'Administrator':
                    AdminView(self.master)
                else:
                    CollaboratorView(self.master, user.username, user.id)
            else:
                self.attempts += 1
                if self.attempts >= 5:
                    self.locked = True
                    self.lock_time = time.time()
                    messagebox.showerror(
                        "Account Locked", 
                        "Too many failed attempts. Try again in 5 minutes"
                    )
                else:
                    messagebox.showerror(
                        "Login Failed", 
                        f"Invalid username or password. {5 - self.attempts} attempts remaining"
                    )