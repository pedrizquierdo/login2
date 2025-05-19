from tkinter import Tk, Frame, Label, Button, Listbox, Scrollbar, messagebox
from persistence.user_repository import get_all_users, delete_user

class AdminView:
    def __init__(self, master):
        self.master = master
        self.master.title("Admin View")
        self.frame = Frame(self.master)
        self.frame.pack(padx=10, pady=10)

        self.label = Label(self.frame, text="Admin Dashboard", font=("Arial", 16))
        self.label.pack()

        self.user_listbox = Listbox(self.frame, width=50, height=15)
        self.user_listbox.pack(side="left", fill="y")

        self.scrollbar = Scrollbar(self.frame)
        self.scrollbar.pack(side="right", fill="y")

        self.user_listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.user_listbox.yview)

        self.load_users()

        self.delete_button = Button(self.frame, text="Delete User", command=self.delete_selected_user)
        self.delete_button.pack(pady=5)

    def load_users(self):
        users = get_all_users()
        for user in users:
            self.user_listbox.insert("end", f"{user.username} ({user.role})")

    def delete_selected_user(self):
        try:
            selected_index = self.user_listbox.curselection()[0]
            selected_user = self.user_listbox.get(selected_index).split(" ")[0]
            delete_user(selected_user)
            self.user_listbox.delete(selected_index)
            messagebox.showinfo("Success", "User deleted successfully.")
        except IndexError:
            messagebox.showwarning("Warning", "Please select a user to delete.")