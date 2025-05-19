from tkinter import Tk
from gui.login_window import LoginWindow

def main():
    root = Tk()
    root.title("Secure Login System")
    root.geometry("400x300")
    
    login_window = LoginWindow(root)
    login_window.pack(expand=True, fill='both')
    
    root.mainloop()

if __name__ == "__main__":
    main()

