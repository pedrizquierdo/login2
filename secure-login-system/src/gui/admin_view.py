from tkinter import Toplevel, Label, Button, StringVar, Entry, messagebox, Listbox, END
from persistence.user_repository import create_user, get_all_users, delete_user_by_id
from utils.password_utils import hash_password
from persistence.base_datos import SessionLocal

class AdminView(Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Admin Menu")
        self.geometry("350x300")
        Label(self, text="Admin Menu", font=("Arial", 16)).pack(pady=10)

        Button(self, text="Register New User", command=self.open_register_user).pack(pady=10)
        Button(self, text="View Users", command=self.open_user_list).pack(pady=10)
        Button(self, text="Logout", command=self.logout).pack(pady=10)

    def open_register_user(self):
        RegisterUserWindow(self)

    def open_user_list(self):
        self.withdraw()  # Oculta la ventana de admin
        UserListWindow(self)

    def logout(self):
        self.destroy()
        self.master.deiconify()  # Muestra la ventana principal (login)

class UserListWindow(Toplevel):
    def __init__(self, admin_window):
        super().__init__(admin_window)
        self.admin_window = admin_window
        self.title("User List")
        self.geometry("400x350")
        Label(self, text="Registered Users", font=("Arial", 14)).pack(pady=10)

        self.user_listbox = Listbox(self, width=50)
        self.user_listbox.pack(pady=10, fill='both', expand=True)

        Button(self, text="Delete Selected User", command=self.delete_selected_user).pack(pady=10)
        Button(self, text="Volver", command=self.volver).pack(pady=5)

        self.refresh_user_list()

    def refresh_user_list(self):
        self.user_listbox.delete(0, END)
        with SessionLocal() as session:
            users = get_all_users(session)
            for user in users:
                self.user_listbox.insert(END, f"{user.id} - {user.username} - {user.role}")

    def delete_selected_user(self):
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to delete.")
            return
        user_info = self.user_listbox.get(selection[0])
        user_id = int(user_info.split(" - ")[0])
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete user ID {user_id}?")
        if confirm:
            with SessionLocal() as session:
                if delete_user_by_id(session, user_id):
                    messagebox.showinfo("Success", "User deleted successfully.")
                    self.refresh_user_list()
                else:
                    messagebox.showerror("Error", "Failed to delete user.")

    def volver(self):
        self.destroy()
        self.admin_window.deiconify()


class RegisterUserWindow(Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Register User")
        self.geometry("350x300")

        self.username_var = StringVar()
        self.email_var = StringVar()
        self.password_var = StringVar()
        self.role_var = StringVar(value="Collaborator")

        Label(self, text="Username").pack()
        Entry(self, textvariable=self.username_var).pack()
        Label(self, text="Email").pack()
        Entry(self, textvariable=self.email_var).pack()
        Label(self, text="Password").pack()
        Entry(self, textvariable=self.password_var, show='*').pack()
        Label(self, text="Role (Collaborator/Administrator)").pack()
        Entry(self, textvariable=self.role_var).pack()

        Button(self, text="Register", command=self.register_user).pack(pady=10)

    def register_user(self):
        username = self.username_var.get()
        email = self.email_var.get()
        password = self.password_var.get()
        role = self.role_var.get()
        if not username or not email or not password or role not in ["Collaborator", "Administrator"]:
            messagebox.showerror("Error", "All fields are required and role must be Collaborator or Administrator.")
            return
        hashed_password = hash_password(password)
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode('utf-8')
        with SessionLocal() as session:
            try:
                create_user(session, username, email, hashed_password, role)
                messagebox.showinfo("Success", "User registered successfully!")
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Registration failed: {e}")
    
    