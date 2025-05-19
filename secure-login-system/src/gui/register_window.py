from tkinter import Tk, Label, Entry, Button, StringVar, messagebox
from sqlalchemy.orm import Session
from models.user import User
from persistence.user_repository import create_user
from utils.password_utils import hash_password

class RegisterWindow:
    def __init__(self, master: Tk):
        self.master = master
        self.master.title("Register")
        self.master.geometry("300x300")

        self.username_var = StringVar()
        self.email_var = StringVar()
        self.password_var = StringVar()

        Label(master, text="Username").pack()
        Entry(master, textvariable=self.username_var).pack()

        Label(master, text="Email").pack()
        Entry(master, textvariable=self.email_var).pack()

        Label(master, text="Password").pack()
        Entry(master, textvariable=self.password_var, show='*').pack()

        Button(master, text="Register", command=self.register_user).pack()

    def register_user(self):
        username = self.username_var.get()
        email = self.email_var.get()
        password = self.password_var.get()

        if not username or not email or not password:
            messagebox.showerror("Error", "All fields are required!")
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