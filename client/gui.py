import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, QStackedWidget, QGraphicsDropShadowEffect, QSpacerItem, QSizePolicy
from PyQt5.QtCore import Qt
from client import login, register, generate_keys  # Import functions from client.py
from cryptography.hazmat.primitives import hashes

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumChat")
        self.setGeometry(100, 100, 300, 500)
        
        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_menu = QWidget()
        self.login_menu = LoginWindow(self)
        self.register_menu = RegisterWindow(self)
        self.user_menu = UserMenu(self)
        
        self.init_main_menu()
        
        self.central_widget.addWidget(self.main_menu)
        self.central_widget.addWidget(self.login_menu)
        self.central_widget.addWidget(self.register_menu)
        self.central_widget.addWidget(self.user_menu)

    def init_main_menu(self):
        layout = QVBoxLayout()
        
        welcome_label = QLabel("Welcome to QuantumChat!", self)
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)
        
        style = """
    QPushButton {
        background-color: white;
        border: 2px solid #1A1A1A;
        border-radius: 15px;
        color: #3B3B3B;
        font-size: 16px;
        font-weight: 600;
        line-height: normal;
        min-height: 60px;
        padding: 16px 24px;
        text-align: center;
        text-decoration: none;
        width: 100%;
    
    }
    QPushButton:hover {
        color: #fff;
        background-color: #1A1A1A;
    }
"""

        login_button = QPushButton("Login", self)
        login_button.clicked.connect(lambda: self.central_widget.setCurrentWidget(self.login_menu))
        login_button.setStyleSheet(style)
        effect = QGraphicsDropShadowEffect()
        effect.setOffset(5, 5)
        effect.setBlurRadius(15)
        login_button.setGraphicsEffect(effect)
        layout.addWidget(login_button)
        
        register_button = QPushButton("Register", self)
        register_button.clicked.connect(lambda: self.central_widget.setCurrentWidget(self.register_menu))
        register_button.setStyleSheet(style)
        effect2 = QGraphicsDropShadowEffect()
        effect2.setOffset(5, 5)
        effect2.setBlurRadius(15)
        register_button.setGraphicsEffect(effect2)
        layout.addWidget(register_button)
        
        exit_button = QPushButton("Exit", self)
        exit_button.clicked.connect(self.close)
        exit_button.setStyleSheet("""
    QPushButton {
        background-color: white;
        border: 2px solid #1A1A1A;
        border-radius: 15px;
        color: #3B3B3B;
        font-size: 16px;
        font-weight: 600;
        line-height: normal;
        min-height: 30px;
        padding: 16px 24px;
        text-align: center;
        text-decoration: none;
        width: 100%;
    
    }
    QPushButton:hover {
        color: #fff;
        background-color: #d12219;
    }
""")    
        effect3 = QGraphicsDropShadowEffect()
        effect3.setOffset(5, 5)
        effect3.setBlurRadius(15)
        exit_button.setGraphicsEffect(effect3)
        #exit_button.setFixedWidth(200)
        layout.addWidget(exit_button)
        
        self.main_menu.setLayout(layout)

class LoginWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Login")
        
        self.layout = QVBoxLayout()
        
        self.username_label = QLabel("Username:")
        self.layout.addWidget(self.username_label)
        self.username_input = QLineEdit()
        self.layout.addWidget(self.username_input)
        
        self.password_label = QLabel("Password:")
        self.layout.addWidget(self.password_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        self.layout.addWidget(self.login_button)
        
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(lambda: self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu))
        self.layout.addWidget(self.back_button)
        
        self.setLayout(self.layout)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        # Hash the password
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        password_hashed = digest.finalize().hex()
        
        response = login(username, password_hashed)
        if response.status_code == 200:
            self.main_window.user_menu.set_username(username)
            self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)
        else:
            QMessageBox.warning(self, "Error", response.text)

class RegisterWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Register")
        
        self.layout = QVBoxLayout()
        
        self.spacer_top = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_top)
        
        self.username_label = QLabel("Username:")
        self.username_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.layout.addWidget(self.username_label, alignment=Qt.AlignCenter)
        
        self.username_input = QLineEdit()
        self.username_input.setFixedSize(300, 40)  # Aumenta le dimensioni del box di input
        self.username_input.setStyleSheet("font-size: 16px; padding: 10px;")
        self.layout.addWidget(self.username_input, alignment=Qt.AlignCenter)
        
        self.password_label = QLabel("Password:")
        self.password_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.layout.addWidget(self.password_label, alignment=Qt.AlignCenter)
        
        self.password_input = QLineEdit()
        self.password_input.setFixedSize(300, 40)  # Aumenta le dimensioni del box di input
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("font-size: 16px; padding: 10px;")
        self.layout.addWidget(self.password_input, alignment=Qt.AlignCenter)
        
        self.register_button = QPushButton("Register")
        self.register_button.setFixedSize(200, 50)  # Aumenta le dimensioni del bottone
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: white;
                border: 2px solid #1A1A1A;
                border-radius: 15px;
                color: #3B3B3B;
                font-weight: 600;
                padding: 16px 24px;
                text-align: center;
                text-decoration: none;
            }
            QPushButton:hover {
                color: #fff;
                background-color: #1A1A1A
            }
        """)
        self.register_button.clicked.connect(self.register)
        self.layout.addWidget(self.register_button, alignment=Qt.AlignCenter)
        
        self.back_button = QPushButton("Back")
        self.back_button.setFixedSize(200, 50)  # Aumenta le dimensioni del bottone
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: white;
                border: 2px solid #1A1A1A;
                border-radius: 15px;
                color: #3B3B3B;
                font-weight: 600;
                padding: 16px 24px;
                text-align: center;
                text-decoration: none;
            }
            QPushButton:hover {
                color: #fff;
                background-color: #d12219;
            }
        """)
        self.back_button.clicked.connect(lambda: self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu))
        self.layout.addWidget(self.back_button, alignment=Qt.AlignCenter)
        
        self.spacer_bottom = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_bottom)
        
        self.setLayout(self.layout)
    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        # Hash the password
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        password_hashed = digest.finalize().hex()
        
        public_keys = generate_keys()
        
        response = register(username, password_hashed, public_keys)
        if response.status_code == 200:
            self.main_window.user_menu.set_username(username)
            self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)
        else:
            QMessageBox.warning(self, "Error", response.text)

class UserMenu(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("User Menu")
        
        self.layout = QVBoxLayout()
        
        self.welcome_label = QLabel()
        self.welcome_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.welcome_label)
        
        self.chats_button = QPushButton("Chats")
        self.chats_button.clicked.connect(self.show_chats)
        self.layout.addWidget(self.chats_button)
        
        self.groups_button = QPushButton("Groups")
        self.groups_button.clicked.connect(self.show_groups)
        self.layout.addWidget(self.groups_button)
        
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(lambda: self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu))
        self.layout.addWidget(self.back_button)
        
        self.setLayout(self.layout)

    def set_username(self, username):
        self.welcome_label.setText(f"Welcome {username}!")

    def show_chats(self):
        QMessageBox.information(self, "Chats", "Displaying Chats...")

    def show_groups(self):
        QMessageBox.information(self, "Groups", "Displaying Groups...")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
