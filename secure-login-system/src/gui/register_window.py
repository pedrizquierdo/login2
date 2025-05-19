from tkinter import Tk, Label, Entry, Button, StringVar, Toplevel, messagebox
from sqlalchemy.orm import Session
from models.user import User
from persistence.user_repository import change_password, create_user, update_user
from utils.password_utils import hash_password
from persistence.base_datos import SessionLocal

class RegisterWindow:
    def __init__(self, master: Tk):
        self.master = master
        self.master.title("Register")
        self.master.geometry("300x300")

        self.username_var = StringVar()
        self.email_var = StringVar()
        self.password_var = StringVar()

        self.password_strength = PasswordStrengthIndicator(self, self.password_var)
        self.password_strength.pack()

        Label(master, text="Username").pack()
        Entry(master, textvariable=self.username_var).pack()

        Label(master, text="Email").pack()
        Entry(master, textvariable=self.email_var).pack()

        Label(master, text="Password").pack()
        Entry(master, textvariable=self.password_var, show='*').pack()

        Button(master, text="Register", command=self.register_user).pack()

    def register_user(self):
        username = self.username_var.get().strip()
        email = self.email_var.get().strip()
        password = self.password_var.get()
        
        if not username or not email or not password:
            messagebox.showerror("Error", "All fields are required!")
            return
            
        if len(username) < 4:
            messagebox.showerror("Error", "Username must be at least 4 characters long")
            return
            
        if '@' not in email or '.' not in email:
            messagebox.showerror("Error", "Please enter a valid email address")
            return
            
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return

        hashed_password = hash_password(password)
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode('utf-8')

        with Session() as session:
            if create_user(session, username, email, hashed_password):
                messagebox.showinfo("Success", "User registered successfully!")
                self.master.destroy()
            else:
                messagebox.showerror("Error", "User registration failed. Email may already be in use.")
                
        with Session() as session:
            if create_user(session, username, email, hashed_password):
                messagebox.showinfo("Success", "User registered successfully!")
                self.master.destroy()
            else:
                messagebox.showerror("Error", "User registration failed. Email may already be in use.")

class EditUserWindow(Toplevel):
    def __init__(self, master, user_id):
        super().__init__(master)
        self.user_id = user_id
        self.title("Edit User")
        self.geometry("350x300")
        
        with SessionLocal() as session:
            user = session.query(User).filter(User.id == user_id).first()
            
        self.username_var = StringVar(value=user.username)
        self.email_var = StringVar(value=user.email)
        self.role_var = StringVar(value=user.role)
        
        Label(self, text="Username").pack()
        Entry(self, textvariable=self.username_var).pack()
        
        Label(self, text="Email").pack()
        Entry(self, textvariable=self.email_var).pack()
        
        Label(self, text="Role").pack()
        Entry(self, textvariable=self.role_var).pack()
        
        Button(self, text="Save Changes", command=self.save_changes).pack(pady=10)
        Button(self, text="Change Password", command=self.open_change_password).pack(pady=5)
    
    def save_changes(self):
        with SessionLocal() as session:
            if update_user(
                session,
                self.user_id,
                self.username_var.get(),
                self.email_var.get(),
                self.role_var.get()
            ):
                messagebox.showinfo("Success", "User updated successfully")
                self.destroy()
            else:
                messagebox.showerror("Error", "Failed to update user")
    
    def open_change_password(self):
        ChangePasswordWindow(self, self.user_id)

class ChangePasswordWindow(Toplevel):
    def __init__(self, master, user_id):
        super().__init__(master)
        self.user_id = user_id
        self.title("Change Password")
        self.geometry("300x200")
        
        self.new_password_var = StringVar()
        self.confirm_password_var = StringVar()

        self.password_strength = PasswordStrengthIndicator(self, self.password_var)
        self.password_strength.pack()
        
        Label(self, text="New Password").pack()
        Entry(self, textvariable=self.new_password_var, show='*').pack()
        
        Label(self, text="Confirm Password").pack()
        Entry(self, textvariable=self.confirm_password_var, show='*').pack()
        
        Button(self, text="Change Password", command=self.change_password).pack(pady=10)
    
    def change_password(self):
        new_pass = self.new_password_var.get()
        confirm_pass = self.confirm_password_var.get()
        
        if new_pass != confirm_pass:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        if len(new_pass) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
            
        with SessionLocal() as session:
            if change_password(session, self.user_id, new_pass):
                messagebox.showinfo("Success", "Password changed successfully")
                self.destroy()
            else:
                messagebox.showerror("Error", "Failed to change password")


class PasswordStrengthIndicator(Label):
    def __init__(self, master, password_var):
        super().__init__(master, text="Password Strength: Weak", fg="red")
        self.password_var = password_var
        self.password_var.trace_add("write", self.check_strength)
    
    def check_strength(self, *args):
        password = self.password_var.get()
        if len(password) == 0:
            self.config(text="Password Strength: None", fg="gray")
        elif len(password) < 8:
            self.config(text="Password Strength: Weak", fg="red")
        elif len(password) < 12:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            
            if has_upper and has_lower and has_digit:
                self.config(text="Password Strength: Strong", fg="green")
            else:
                self.config(text="Password Strength: Medium", fg="orange")
        else:
            self.config(text="Password Strength: Very Strong", fg="dark green")                
