from tkinter import Toplevel, Label, Button

class CollaboratorView(Toplevel):
    def __init__(self, master, username):
        super().__init__(master)
        self.title("Collaborator Menu")
        self.geometry("300x200")
        Label(self, text=f"Welcome, {username}!", font=("Arial", 14)).pack(pady=20)
        Label(self, text="You are a Collaborator.", font=("Arial", 12)).pack(pady=10)
        Button(self, text="Logout", command=self.logout).pack(pady=20)

    def logout(self):
        self.destroy()
        self.master.deiconify()  # Muestra la ventana principal (login)

    def init_ui(self):
        self.master.title("Collaborator Dashboard")
        self.pack(fill='both', expand=True)

        welcome_label = Label(self, text="Welcome to the Collaborator Dashboard", font=("Arial", 16))
        welcome_label.pack(pady=20)

        self.view_data_button = Button(self, text="View Data", command=self.view_data)
        self.view_data_button.pack(pady=10)

        self.logout_button = Button(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)