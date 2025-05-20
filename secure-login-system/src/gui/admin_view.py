import tkinter as tk
from tkinter import ttk, messagebox
from persistence.user_repository import *
from utils.password_utils import *
from persistence.base_datos import SessionLocal
from models.user import User
import time
from persistence.user_repository import change_password, create_user, get_all_users, delete_user_by_id, update_user
from utils.password_utils import hash_password
from persistence.base_datos import SessionLocal
from models.user import User
from gui.register_window import EditUserWindow

class StyledButton(ttk.Button):
    """Botón con estilo consistente"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(style='Accent.TButton')

class ModernFrame(ttk.Frame):
    """Frame con padding y estilo consistente"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(padding=20)

class AdminView(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Panel de Administración")
        self.geometry("600x450")
        self.resizable(False, False)
        
        # Configurar estilo
        self.style = ttk.Style(self)
        self.style.configure('TLabel', font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'), 
                           foreground='white', background='#0078d7')
        
        # Frame principal
        main_frame = ModernFrame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        ttk.Label(main_frame, text="Panel de Administración", 
                 font=('Segoe UI', 16, 'bold')).pack(pady=(0, 20))
        
        # Botones de acción
        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=10)
        
        StyledButton(actions_frame, text="➕ Registrar Nuevo Usuario", 
                   command=self.open_register_user).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        StyledButton(actions_frame, text="👥 Ver Lista de Usuarios", 
                   command=self.open_user_list).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Sección de estadísticas
        stats_frame = ttk.LabelFrame(main_frame, text="Estadísticas", padding=15)
        stats_frame.pack(fill=tk.X, pady=10)
        
        with SessionLocal() as session:
            total_users = len(get_all_users(session))
            admins = len([u for u in get_all_users(session) if u.role == 'Administrator'])
            
        ttk.Label(stats_frame, text=f"Total de usuarios: {total_users}").pack(anchor=tk.W)
        ttk.Label(stats_frame, text=f"Administradores: {admins}").pack(anchor=tk.W)
        ttk.Label(stats_frame, text=f"Colaboradores: {total_users - admins}").pack(anchor=tk.W)
        
        # Botón de salir
        StyledButton(main_frame, text="🔒 Cerrar Sesión", 
                    command=self.logout).pack(pady=(20, 0), ipadx=10, ipady=5)

    def open_register_user(self):
        RegisterUserWindow(self)

    def open_user_list(self):
        self.withdraw()
        UserListWindow(self)

    def logout(self):
        self.destroy()
        self.master.deiconify()

class UserListWindow(tk.Toplevel):
    def __init__(self, admin_window):
        super().__init__(admin_window)
        self.admin_window = admin_window
        self.title("Gestión de Usuarios")
        self.geometry("800x600")
        self.resizable(True, True)
        
        # Configurar estilo
        self.style = ttk.Style(self)
        self.style.configure('Treeview', rowheight=25, font=('Segoe UI', 10))
        self.style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        
        # Frame principal
        main_frame = ModernFrame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        ttk.Label(main_frame, text="Usuarios Registrados", 
                 font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))
        
        # Treeview para mostrar usuarios
        self.tree = ttk.Treeview(main_frame, columns=('ID', 'Username', 'Email', 'Role'), 
                                show='headings', selectmode='browse')
        
        # Configurar columnas
        self.tree.column('ID', width=50, anchor=tk.CENTER)
        self.tree.column('Username', width=150)
        self.tree.column('Email', width=250)
        self.tree.column('Role', width=100, anchor=tk.CENTER)
        
        # Configurar encabezados
        self.tree.heading('ID', text='ID')
        self.tree.heading('Username', text='Usuario')
        self.tree.heading('Email', text='Correo Electrónico')
        self.tree.heading('Role', text='Rol')
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Barra de desplazamiento
        scrollbar = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botones de acción
        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=10)
        
        StyledButton(actions_frame, text="✏️ Editar Usuario", 
                   command=self.edit_selected_user).pack(side=tk.LEFT, padx=5)
        StyledButton(actions_frame, text="🗑️ Eliminar Usuario", 
                   command=self.delete_selected_user).pack(side=tk.LEFT, padx=5)
        StyledButton(actions_frame, text="🔄 Actualizar Lista", 
                   command=self.refresh_user_list).pack(side=tk.LEFT, padx=5)
        StyledButton(actions_frame, text="⬅️ Volver", 
                   command=self.volver).pack(side=tk.RIGHT, padx=5)
        
        self.refresh_user_list()

    def refresh_user_list(self):
        # Limpiar treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Obtener y mostrar usuarios
        with SessionLocal() as session:
            users = get_all_users(session)
            for user in users:
                self.tree.insert('', tk.END, values=(
                    user.id, 
                    user.username, 
                    user.email, 
                    user.role
                ))

    def get_selected_user(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0])['values'][0]  # Retorna el ID

    def edit_selected_user(self):
        user_id = self.get_selected_user()
        if user_id:
            EditUserWindow(self, user_id)
        else:
            messagebox.showwarning("Advertencia", "Por favor seleccione un usuario para editar.")

    def delete_selected_user(self):
        user_id = self.get_selected_user()
        if not user_id:
            messagebox.showwarning("Advertencia", "Por favor seleccione un usuario para eliminar.")
            return
            
        confirm = messagebox.askyesno(
            "Confirmar Eliminación",
            f"¿Está seguro que desea eliminar al usuario con ID {user_id}?",
            icon='warning'
        )
        
        if confirm:
            with SessionLocal() as session:
                if delete_user_by_id(session, user_id):
                    messagebox.showinfo("Éxito", "Usuario eliminado correctamente.")
                    self.refresh_user_list()
                else:
                    messagebox.showerror("Error", "No se pudo eliminar el usuario.")

    def volver(self):
        self.destroy()
        self.admin_window.deiconify()

class RegisterUserWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Registro de Nuevo Usuario")
        self.geometry("500x450")
        self.resizable(False, False)
        
        # Frame principal
        main_frame = ModernFrame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        ttk.Label(main_frame, text="Registrar Nuevo Usuario", 
                 font=('Segoe UI', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Campos del formulario
        ttk.Label(main_frame, text="Nombre de Usuario:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Correo Electrónico:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.email_entry = ttk.Entry(main_frame, width=30)
        self.email_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Contraseña:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(main_frame, width=30, show='•')
        self.password_entry.grid(row=3, column=1, sticky=tk.EW, pady=5)
        
        # Indicador de fortaleza de contraseña
        self.password_strength = PasswordStrengthIndicator(main_frame, self.password_entry)
        self.password_strength.grid(row=4, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Confirmar Contraseña:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.confirm_password_entry = ttk.Entry(main_frame, width=30, show='•')
        self.confirm_password_entry.grid(row=5, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Rol:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.role_combobox = ttk.Combobox(main_frame, values=['Collaborator', 'Administrator'], 
                                         state='readonly')
        self.role_combobox.current(0)
        self.role_combobox.grid(row=6, column=1, sticky=tk.EW, pady=5)
        
        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=7, column=0, columnspan=2, pady=20)
        
        StyledButton(buttons_frame, text="Registrar", command=self.register_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Cancelar", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Configurar grid
        main_frame.columnconfigure(1, weight=1)

    def register_user(self):
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        role = self.role_combobox.get()
        
        # Validaciones
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
            
        if len(username) < 4:
            messagebox.showerror("Error", "El nombre de usuario debe tener al menos 4 caracteres.")
            return
            
        if '@' not in email or '.' not in email:
            messagebox.showerror("Error", "Por favor ingrese un correo electrónico válido.")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            return
            
        if not is_strong_password(password):
            messagebox.showerror(
                "Contraseña Débil",
                "La contraseña debe tener:\n"
                "- Mínimo 8 caracteres\n"
                "- Al menos una mayúscula\n"
                "- Al menos una minúscula\n"
                "- Al menos un número\n"
                "- Al menos un carácter especial"
            )
            return
            
        # Registrar usuario
        hashed_password = hash_password(password)
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode('utf-8')
            
        with SessionLocal() as session:
            try:
                create_user(session, username, email, hashed_password, role)
                messagebox.showinfo("Éxito", "Usuario registrado correctamente.")
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo registrar el usuario: {str(e)}")

class PasswordStrengthIndicator(ttk.Label):
    def __init__(self, master, password_widget):
        super().__init__(master, text="Fortaleza: No evaluada", foreground="gray")
        self.password_var = tk.StringVar()
        password_widget.config(textvariable=self.password_var)  # Asocia el StringVar al Entry
        self.password_var.trace_add('write', self.check_strength)
        
    def check_strength(self, *args):
        password = self.password_var.get()
        
        if not password:
            self.config(text="Fortaleza: No evaluada", foreground="gray")
            return
            
        # Calcular puntaje de fortaleza
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"[0-9]", password): score += 1
        if re.search(r"[^A-Za-z0-9]", password): score += 1
        
        # Actualizar visualización
        if score < 3:
            self.config(text="Fortaleza: Débil", foreground="red")
        elif score < 5:
            self.config(text="Fortaleza: Media", foreground="orange")
        else:
            self.config(text="Fortaleza: Fuerte", foreground="green")