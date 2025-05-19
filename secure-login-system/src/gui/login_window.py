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

        Label(master, text="Username").pack(pady=10)
        Entry(master, textvariable=self.username_var).pack()

        Label(master, text="Password").pack(pady=10)
        Entry(master, textvariable=self.password_var, show='*').pack()

        Button(master, text="Login", command=self.login).pack(pady=20)

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()

        with SessionLocal() as db:
            user = get_user_by_username(db, username)
            if user and verify_password(password, user.password):
                messagebox.showinfo("Login Successful", f"Welcome, {user.username}!")
            # Redirect to user-specific view based on role
                if user.role == 'Administrador':
                    self.master.destroy()  # Close login window
                # Open admin view
                    from src.gui.admin_view import AdminView
                    admin_view = AdminView()
                else:
                    self.master.destroy()  # Close login window
                # Open collaborator view
                    from src.gui.collaborator_view import CollaboratorView
                    collaborator_view = CollaboratorView()
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")