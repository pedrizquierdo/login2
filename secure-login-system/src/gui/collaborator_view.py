import tkinter as tk
from tkinter import ttk, messagebox
from persistence.user_repository import (
    create_user,
    get_all_users,
    update_user,
    change_password
)
from utils.password_utils import (
    hash_password,
    is_strong_password
)
from persistence.base_datos import SessionLocal
from models.user import User
import re
from gui.admin_view import StyledButton, ModernFrame
from gui.register_window import PasswordStrengthIndicator, ChangePasswordWindow


class CollaboratorView(tk.Toplevel):
    def __init__(self, master, username, user_id):
        super().__init__(master)
        self.master = master
        self.user_id = user_id
        self.title(f"Panel de Colaborador - {username}")
        self.geometry("800x600")
        self.resizable(True, True)
        
        # Configurar estilo
        self.style = ttk.Style(self)
        self.style.configure('TLabel', font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'), 
                           foreground='white', background='#28a745')
        
        # Frame principal
        main_frame = ModernFrame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        ttk.Label(main_frame, text=f"Bienvenido, {username}", 
                 font=('Segoe UI', 16, 'bold')).pack(pady=(0, 20))
        
        # Sección de gestión de colaboradores
        collab_frame = ttk.LabelFrame(main_frame, text="Gestión de Colaboradores", padding=15)
        collab_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Treeview para mostrar colaboradores
        self.tree = ttk.Treeview(collab_frame, columns=('ID', 'Username', 'Email'), 
                                show='headings', selectmode='browse')
        
        # Configurar columnas
        self.tree.column('ID', width=50, anchor=tk.CENTER)
        self.tree.column('Username', width=150)
        self.tree.column('Email', width=250)
        
        # Configurar encabezados
        self.tree.heading('ID', text='ID')
        self.tree.heading('Username', text='Usuario')
        self.tree.heading('Email', text='Correo Electrónico')
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Barra de desplazamiento
        scrollbar = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botones de acción
        actions_frame = ttk.Frame(collab_frame)
        actions_frame.pack(fill=tk.X, pady=10)
        
        StyledButton(actions_frame, text="➕ Nuevo Colaborador", 
                   command=self.open_register_collaborator).pack(side=tk.LEFT, padx=5)
        StyledButton(actions_frame, text="✏️ Editar Colaborador", 
                   command=self.edit_selected_collaborator).pack(side=tk.LEFT, padx=5)
        StyledButton(actions_frame, text="🔄 Actualizar Lista", 
                   command=self.refresh_collaborator_list).pack(side=tk.LEFT, padx=5)
        
        # Botón de salir
        StyledButton(main_frame, text="🔒 Cerrar Sesión", 
                    command=self.logout).pack(pady=(20, 0), ipadx=10, ipady=5)
        
        self.refresh_collaborator_list()

    def refresh_collaborator_list(self):
        """Actualiza la lista mostrando solo colaboradores"""
        # Limpiar treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Obtener y mostrar solo colaboradores
        with SessionLocal() as session:
            users = get_all_users(session)
            for user in users:
                if user.role == 'Collaborator' and user.id != self.user_id:  # Excluir al usuario actual
                    self.tree.insert('', tk.END, values=(
                        user.id, 
                        user.username, 
                        user.email
                    ))

    def get_selected_collaborator(self):
        """Obtiene el ID del colaborador seleccionado"""
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0])['values'][0]  # Retorna el ID

    def open_register_collaborator(self):
        """Abre ventana para registrar nuevo colaborador"""
        RegisterCollaboratorWindow(self)

    def edit_selected_collaborator(self):
        """Abre ventana para editar colaborador seleccionado"""
        collab_id = self.get_selected_collaborator()
        if collab_id:
            EditCollaboratorWindow(self, collab_id)
        else:
            messagebox.showwarning("Advertencia", "Por favor seleccione un colaborador para editar.")

    def logout(self):
        """Cierra la sesión"""
        self.destroy()
        self.master.deiconify()


class RegisterCollaboratorWindow(tk.Toplevel):
    """Ventana especializada para registrar nuevos colaboradores"""
    def __init__(self, master):
        super().__init__(master)
        self.title("Registrar Nuevo Colaborador")
        self.geometry("500x450")  # Aumenté un poco el tamaño para mejor visualización
        self.resizable(False, False)
        
        # Frame principal
        main_frame = ModernFrame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        ttk.Label(main_frame, text="Registrar Nuevo Colaborador", 
                 font=('Segoe UI', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Campos del formulario
        ttk.Label(main_frame, text="Nombre de Usuario:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Correo Electrónico:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.email_entry = ttk.Entry(main_frame, width=30)
        self.email_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Contraseña:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, width=30, show='•', textvariable=self.password_var)
        self.password_entry.grid(row=3, column=1, sticky=tk.EW, pady=5)
        
        # Indicador de fortaleza de contraseña
        self.password_strength = PasswordStrengthIndicator(main_frame, self.password_var)
        self.password_strength.grid(row=4, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Confirmar Contraseña:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(main_frame, width=30, show='•', textvariable=self.confirm_password_var)
        self.confirm_password_entry.grid(row=5, column=1, sticky=tk.EW, pady=5)
        
        # Frame para botones (mejorado)
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=7, column=0, columnspan=2, pady=(20, 0))
        
        # Botón de Guardar (mejorado)
        save_button = StyledButton(
            buttons_frame, 
            text="💾 Guardar Colaborador",
            command=self.register_collaborator,
            style='Accent.TButton'
        )
        save_button.pack(side=tk.LEFT, padx=5, ipadx=10, ipady=5)
        
        # Botón de Cancelar (mejorado)
        cancel_button = ttk.Button(
            buttons_frame,
            text="❌ Cancelar",
            command=self.destroy,
            style='TButton'
        )
        cancel_button.pack(side=tk.RIGHT, padx=5, ipadx=10, ipady=5)
        
        # Configurar grid
        main_frame.columnconfigure(1, weight=1)
        
        # Enfocar el primer campo al abrir la ventana
        self.username_entry.focus_set()
        
        # Configurar tecla Enter para guardar
        self.bind('<Return>', lambda event: self.register_collaborator())

    def register_collaborator(self):
        """Registra un nuevo colaborador (siempre con rol Collaborator)"""
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        role = 'Collaborator'  # Fijo para esta ventana
        
        # Validaciones
        errors = []
        if not username:
            errors.append("El nombre de usuario es obligatorio")
        elif len(username) < 4:
            errors.append("El nombre de usuario debe tener al menos 4 caracteres")
            
        if not email:
            errors.append("El correo electrónico es obligatorio")
        elif '@' not in email or '.' not in email:
            errors.append("Por favor ingrese un correo electrónico válido")
            
        if not password:
            errors.append("La contraseña es obligatoria")
        elif len(password) < 8:
            errors.append("La contraseña debe tener al menos 8 caracteres")
        elif not is_strong_password(password):
            errors.append("La contraseña no cumple con los requisitos de seguridad")
            
        if password != confirm_password:
            errors.append("Las contraseñas no coinciden")
            
        if errors:
            messagebox.showerror(
                "Errores en el formulario",
                "\n".join(f"• {error}" for error in errors),
                parent=self
            )
            return
            
        # Registrar usuario como colaborador
        hashed_password = hash_password(password)
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode('utf-8')
            
        with SessionLocal() as session:
            try:
                create_user(session, username, email, hashed_password, role)
                messagebox.showinfo(
                    "Éxito", 
                    "Colaborador registrado correctamente.",
                    parent=self
                )
                if hasattr(self.master, 'refresh_collaborator_list'):
                    self.master.refresh_collaborator_list()
                self.destroy()
            except Exception as e:
                messagebox.showerror(
                    "Error", 
                    f"No se pudo registrar el colaborador: {str(e)}",
                    parent=self
                )

    def register_collaborator(self):
        """Registra un nuevo colaborador (siempre con rol Collaborator)"""
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        role = 'Collaborator'  # Fijo para esta ventana
        
        # Validaciones (igual que antes)
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
            
        # Registrar usuario como colaborador
        hashed_password = hash_password(password)
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode('utf-8')
            
        with SessionLocal() as session:
            try:
                create_user(session, username, email, hashed_password, role)
                messagebox.showinfo("Éxito", "Colaborador registrado correctamente.")
                self.master.refresh_collaborator_list()
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo registrar el colaborador: {str(e)}")


class EditCollaboratorWindow(tk.Toplevel):
    """Ventana para editar colaboradores existentes"""
    def __init__(self, master, collab_id):
        super().__init__(master)
        self.collab_id = collab_id
        self.title("Editar Colaborador")
        self.geometry("500x300")
        self.resizable(False, False)
        
        # Frame principal
        main_frame = ModernFrame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Obtener datos del colaborador
        with SessionLocal() as session:
            self.collaborator = session.query(User).filter(User.id == collab_id).first()
        
        # Título
        ttk.Label(main_frame, text=f"Editando a {self.collaborator.username}", 
                 font=('Segoe UI', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Campos editables
        ttk.Label(main_frame, text="Nombre de Usuario:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.insert(0, self.collaborator.username)
        self.username_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(main_frame, text="Correo Electrónico:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.email_entry = ttk.Entry(main_frame, width=30)
        self.email_entry.insert(0, self.collaborator.email)
        self.email_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        # Botones
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        StyledButton(buttons_frame, text="Guardar Cambios", 
                   command=self.save_changes).pack(side=tk.LEFT, padx=5)
        StyledButton(buttons_frame, text="Cambiar Contraseña", 
                   command=self.open_change_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Cancelar", 
                  command=self.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Configurar grid
        main_frame.columnconfigure(1, weight=1)

    def save_changes(self):
        """Guarda los cambios del colaborador"""
        new_username = self.username_entry.get().strip()
        new_email = self.email_entry.get().strip()
        
        if not new_username or not new_email:
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
            
        with SessionLocal() as session:
            if update_user(
                session,
                self.collab_id,
                username=new_username,
                email=new_email,
                role='Collaborator'  # Siempre mantiene el rol de colaborador
            ):
                messagebox.showinfo("Éxito", "Cambios guardados correctamente.")
                self.master.refresh_collaborator_list()
                self.destroy()
            else:
                messagebox.showerror("Error", "No se pudieron guardar los cambios.")

    def open_change_password(self):
        """Abre ventana para cambiar contraseña"""
        ChangePasswordWindow(self, self.collab_id)