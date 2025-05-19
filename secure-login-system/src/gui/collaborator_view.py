from tkinter import Frame, Label, Button, messagebox
from services.auth_service import AuthService

class CollaboratorView(Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.init_ui()

    def init_ui(self):
        self.master.title("Collaborator Dashboard")
        self.pack(fill='both', expand=True)

        welcome_label = Label(self, text="Welcome to the Collaborator Dashboard", font=("Arial", 16))
        welcome_label.pack(pady=20)

        self.view_data_button = Button(self, text="View Data", command=self.view_data)
        self.view_data_button.pack(pady=10)

        self.logout_button = Button(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

    def view_data(self):
        # Placeholder for data viewing functionality
        messagebox.showinfo("View Data", "Data viewing functionality is not implemented yet.")

    def logout(self):
        # Placeholder for logout functionality
        messagebox.showinfo("Logout", "You have been logged out.")
        self.master.destroy()  # Close the application or redirect to login window