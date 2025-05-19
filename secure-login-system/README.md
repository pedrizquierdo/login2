# Secure Login System

This project is a secure login system that includes user registration and login functionality with a graphical user interface (GUI). It is designed to provide different views for collaborators and administrators based on the logged-in user. The application ensures proper validation to prevent SQL injection vulnerabilities and uses bcrypt for password encryption.

## Features

- User registration with password encryption
- User login with role-based access
- Administrator view for managing user data
- Collaborator view for accessing relevant data
- Secure handling of user credentials

## Project Structure

```
secure-login-system
├── src
│   ├── gui
│   │   ├── admin_view.py
│   │   ├── collaborator_view.py
│   │   ├── login_window.py
│   │   └── register_window.py
│   ├── models
│   │   └── user.py
│   ├── persistence
│   │   ├── base_datos.py
│   │   └── user_repository.py
│   ├── services
│   │   └── auth_service.py
│   ├── utils
│   │   └── password_utils.py
│   └── main.py
├── requirements.txt
└── README.md
```

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
   cd secure-login-system
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the database connection in `src/persistence/base_datos.py` as needed.

4. Create the database tables by running the following command in a Python shell:
   ```python
   from src.persistence.base_datos import create_tables
   create_tables()
   ```

5. Run the application:
   ```
   python src/main.py
   ```

## Usage Guidelines

- To register a new user, navigate to the registration window and fill in the required fields.
- After registration, users can log in using their credentials.
- Administrators have access to additional functionalities for managing users.

## Security Considerations

- Passwords are hashed using bcrypt to ensure secure storage.
- Input validation is implemented to prevent SQL injection attacks.

## Acknowledgments

This project utilizes various libraries and frameworks, including Flask, SQLAlchemy, and bcrypt, to provide a robust and secure user authentication system.