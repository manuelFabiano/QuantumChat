from datetime import datetime
import sys
import time
from PyQt5 import QtCore
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, QStackedWidget, QGraphicsDropShadowEffect, QSpacerItem, QSizePolicy, QListWidget, QListWidgetItem, QHBoxLayout, QTextEdit, QDialog
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QCursor
import secrets
from cryptography.hazmat.primitives import hashes
import random
from db_connections import *
from chats import *

style = """
    QPushButton {
        background-color: #5CB7DA;
        border: 2px solid #28a4d4;
        border-radius: 15px;
        color: #fff;
        font-size: 20px;
        font-weight: 600;
        line-height: normal;
        text-align: center;
        text-decoration: none;
    
    }
    QPushButton:hover {
        color: #fff;
        background-color: #6fcaed;
    }
"""

COLORS = [
    "red", "green", "blue", "purple", "orange", "pink",
    "brown", "black", "magenta", "lime",
    "maroon", "navy", "olive", "teal", "fuchsia"
]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumChat")
        self.setContentsMargins(0, 0, 0, 0)
        self.setFixedSize(360, 640)
        self.setStyleSheet("background-color: #fcfcfc;")
        
        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_menu = QWidget()
        self.login_menu = LoginWindow(self)
        self.register_menu = RegisterWindow(self)
        self.user_menu = UserMenu(self)
        self.chat_list_window = ChatListWindow(self)
        self.chat_window = ChatWindow(self)
        self.group_list_window = GroupListWindow(self)
    
        self.init_main_menu()
        
        self.central_widget.addWidget(self.main_menu)
        self.central_widget.addWidget(self.login_menu)
        self.central_widget.addWidget(self.register_menu)
        self.central_widget.addWidget(self.user_menu)
        self.central_widget.addWidget(self.chat_list_window)
        self.central_widget.addWidget(self.chat_window)
        self.central_widget.addWidget(self.group_list_window)

    def init_main_menu(self):
        layout = QVBoxLayout()
        
        # Adding spacing between the top of the window and the logo
        layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Adding the logo
        logo_label = QLabel(self)
        pixmap = QPixmap("logo.png").scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Adding spacing between the logo and buttons
        layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Login button
        login_button = QPushButton("Login", self)
        login_button.clicked.connect(lambda: self.central_widget.setCurrentWidget(self.login_menu))
        login_button.setStyleSheet(style)
        login_button.setCursor(QCursor(Qt.PointingHandCursor))
        login_button.setFixedSize(180, 60)
        effect = QGraphicsDropShadowEffect()
        effect.setOffset(5, 5)
        effect.setBlurRadius(15)
        login_button.setGraphicsEffect(effect)
        layout.addWidget(login_button, alignment=Qt.AlignCenter)
        
        # Register button
        register_button = QPushButton("Register", self)
        register_button.clicked.connect(lambda: self.central_widget.setCurrentWidget(self.register_menu))
        register_button.setStyleSheet(style)
        register_button.setCursor(QCursor(Qt.PointingHandCursor))
        register_button.setFixedSize(180, 60)
        effect2 = QGraphicsDropShadowEffect()
        effect2.setOffset(5, 5)
        effect2.setBlurRadius(15)
        register_button.setGraphicsEffect(effect2)
        layout.addWidget(register_button, alignment=Qt.AlignCenter)
        
        # Exit button
        exit_button = QPushButton("Exit", self)
        exit_button.clicked.connect(self.close)
        exit_button.setCursor(QCursor(Qt.PointingHandCursor))
        exit_button.setFixedSize(120, 50)
        exit_button.setStyleSheet("""
        QPushButton {
            background-color: #e31717;
            border: 2px solid #c20606;
            border-radius: 15px;
            color: #fff;
            font-size: 20px;
            font-weight: 600;
            line-height: normal;
            text-align: center;
            text-decoration: none;
    
        }
        QPushButton:hover {
            color: #fff;
            background-color: #eb3636;
        }
        """)    
        effect3 = QGraphicsDropShadowEffect()
        effect3.setOffset(5, 5)
        effect3.setBlurRadius(15)
        exit_button.setGraphicsEffect(effect3)
        layout.addWidget(exit_button, alignment=Qt.AlignCenter)

        # Reducing the vertical spacing between widgets
        layout.setSpacing(15)

        # Adding spacing between the logo and buttons
        layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        self.main_menu.setLayout(layout)

class LoginWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Login")
        self.layout = QVBoxLayout()
        
        # Adding spacing 
        self.spacer_top = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_top)
        
        # Adding the usename label
        self.username_label = QLabel("Username:")
        self.username_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.layout.addWidget(self.username_label, alignment=Qt.AlignCenter)
        
        # Adding the username input
        self.username_input = QLineEdit()
        self.username_input.setFixedSize(250, 40)  # Aumenta le dimensioni del box di input
        self.username_input.setStyleSheet("font-size: 16px; padding: 10px; background-color: #f5f5f5; border: 1px solid #e6e6e6; border-radius: 5px;")
        self.layout.addWidget(self.username_input, alignment=Qt.AlignCenter)
        
        # Adding password label
        self.password_label = QLabel("Password:")
        self.password_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.layout.addWidget(self.password_label, alignment=Qt.AlignCenter)
        
        # Adding password input
        self.password_input = QLineEdit()
        self.password_input.setFixedSize(250, 40)  # Aumenta le dimensioni del box di input
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("font-size: 16px; padding: 10px; background-color: #f5f5f5; border: 1px solid #e6e6e6; border-radius: 5px;")
        self.layout.addWidget(self.password_input, alignment=Qt.AlignCenter)
        
        self.layout.setSpacing(15)

        # Adding the login button
        self.register_button = QPushButton("Login")
        self.register_button.setFixedSize(150, 50)  # Aumenta le dimensioni del bottone
        self.register_button.setStyleSheet(style)
        self.register_button.clicked.connect(self.login)
        effect = QGraphicsDropShadowEffect()
        effect.setOffset(3, 3)
        effect.setBlurRadius(30)
        self.register_button.setGraphicsEffect(effect)
        self.register_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.layout.addWidget(self.register_button, alignment=Qt.AlignCenter)
        
        self.back_button = QPushButton("Back")
        self.back_button.setFixedSize(100, 40)  # Aumenta le dimensioni del bottone
        self.back_button.setStyleSheet("""
        QPushButton {
        background-color: #e31717;
        border: 2px solid #c20606;
        border-radius: 15px;
        color: #fff;
        font-size: 20px;
        font-weight: 600;
        line-height: normal;
        text-align: center;
        text-decoration: none;
    
    }
    QPushButton:hover {
        color: #fff;
        background-color: #eb3636;
    }
        """)
        self.back_button.clicked.connect(self.back)
        effect2 = QGraphicsDropShadowEffect()
        effect2.setOffset(3, 3)
        effect2.setBlurRadius(30)
        self.back_button.setGraphicsEffect(effect2)
        self.back_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.layout.addWidget(self.back_button, alignment=Qt.AlignCenter)
        
        self.spacer_bottom = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_bottom)
        
        self.setLayout(self.layout)

    def back(self):
        self.username_input.clear()
        self.password_input.clear()
        self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        # Hash the password
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        password_hashed = digest.finalize().hex()
        
        try:
            response = login(username, password_hashed)
            
            if response.status_code == 200:
                self.username_input.clear()
                self.password_input.clear()
                self.main_window.user_menu.username = username
                self.main_window.user_menu.set_username(username)
                # After the login, connect to local db
                self.main_window.user_menu.db = connect_local_db(username)
                self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)
                
            else:
                QMessageBox.warning(self, "Error", response.json()["error"])
        except Exception as e:
            QMessageBox.warning(self, "Error", "Unable to connect to the server")


class RegisterWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Register")
        
        self.layout = QVBoxLayout()
        self.layout.setSpacing(15)
        self.spacer_top = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_top)
        
        self.username_label = QLabel("Username:")
        self.username_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.layout.addWidget(self.username_label, alignment=Qt.AlignCenter)
        
        self.username_input = QLineEdit()
        self.username_input.setFixedSize(250, 40)  # Aumenta le dimensioni del box di input
        self.username_input.setStyleSheet("font-size: 16px; padding: 10px; background-color: #f5f5f5; border: 1px solid #e6e6e6; border-radius: 5px;")
        self.layout.addWidget(self.username_input, alignment=Qt.AlignCenter)
        
        self.password_label = QLabel("Password:")
        self.password_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.layout.addWidget(self.password_label, alignment=Qt.AlignCenter)
        
        self.password_input = QLineEdit()
        self.password_input.setFixedSize(250, 40)  # Aumenta le dimensioni del box di input
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("font-size: 16px; padding: 10px; background-color: #f5f5f5; border: 1px solid #e6e6e6; border-radius: 5px;")
        self.layout.addWidget(self.password_input, alignment=Qt.AlignCenter)
        
        self.register_button = QPushButton("Register")
        self.register_button.setFixedSize(150, 50)  # Aumenta le dimensioni del bottone
        self.register_button.setStyleSheet(style)
        self.register_button.clicked.connect(self.register)
        effect = QGraphicsDropShadowEffect()
        effect.setOffset(3, 3)
        effect.setBlurRadius(30)
        self.register_button.setGraphicsEffect(effect)
        self.register_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.layout.addWidget(self.register_button, alignment=Qt.AlignCenter)
        
        self.back_button = QPushButton("Back")
        self.back_button.setFixedSize(100, 40)  # Aumenta le dimensioni del bottone
        self.back_button.setStyleSheet("""
            QPushButton {
        background-color: #e31717;
        border: 2px solid #c20606;
        border-radius: 15px;
        color: #fff;
        font-size: 20px;
        font-weight: 600;
        line-height: normal;
        text-align: center;
        text-decoration: none;
    
    }
    QPushButton:hover {
        color: #fff;
        background-color: #eb3636;
    }
        """)
        self.back_button.clicked.connect(self.back)
        effect2 = QGraphicsDropShadowEffect()
        effect2.setOffset(3, 3)
        effect2.setBlurRadius(30)
        self.back_button.setGraphicsEffect(effect2)
        self.back_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.layout.addWidget(self.back_button, alignment=Qt.AlignCenter)
        
        self.spacer_bottom = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_bottom)
        
        self.setLayout(self.layout)

    def back(self):
        self.username_input.clear()
        self.password_input.clear()
        self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu)
    # Function for register logic
    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        # Hash the password
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        password_hashed = digest.finalize().hex()
        
        keys = generate_keys()
        
        try:
            response = register(username, password_hashed, keys[1])
            if response.status_code == 200:
                self.username_input.clear()
                self.password_input.clear()
                # After the login, connect to local db
                self.main_window.user_menu.db = connect_local_db(username)
                # Save the keys in the local db
                export_keys(username,keys[0], self.main_window.user_menu.db.keys)
                # Change window
                self.main_window.user_menu.set_username(username)
                self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)
            else:
                QMessageBox.warning(self, "Error", response.json()["error"])
        except Exception as e:
            QMessageBox.warning(self, "Error", "Unable to connect to the server")

class UserMenu(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("User Menu")
        
        self.layout = QVBoxLayout()
        self.layout.setSpacing(15)
        self.spacer_top = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_top)
        
        self.welcome_label = QLabel()
        self.welcome_label.setStyleSheet("font-size: 30px; font-weight: bold;")
        self.welcome_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.welcome_label)

        self.spacer_mid = QSpacerItem(10, 10, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_mid)

        self.chats_button = QPushButton("Chats")
        self.chats_button.clicked.connect(self.show_chats)
        self.chats_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.chats_button.setFixedSize(150, 50)
        self.chats_button.setStyleSheet(style)
        effect = QGraphicsDropShadowEffect()
        effect.setOffset(5, 5)
        effect.setBlurRadius(15)
        self.chats_button.setGraphicsEffect(effect)
        self.layout.addWidget(self.chats_button, alignment=Qt.AlignCenter)
        
        self.groups_button = QPushButton("Groups")
        self.groups_button.clicked.connect(self.show_groups)
        self.groups_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.groups_button.setFixedSize(150, 50)
        self.groups_button.setStyleSheet(style)
        effect2 = QGraphicsDropShadowEffect()
        effect2.setOffset(5, 5)
        effect2.setBlurRadius(15)
        self.groups_button.setGraphicsEffect(effect2)
        self.layout.addWidget(self.groups_button, alignment=Qt.AlignCenter)
        
        self.back_button = QPushButton("Logout")
        self.back_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.back_button.clicked.connect(lambda: self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu))
        self.back_button.setFixedSize(100, 40)  # Aumenta le dimensioni del bottone
        effect3 = QGraphicsDropShadowEffect()
        effect3.setOffset(5, 5)
        effect3.setBlurRadius(15)
        self.back_button.setGraphicsEffect(effect3)
        self.back_button.setStyleSheet("""
            QPushButton {
        background-color: #e31717;
        border: 2px solid #c20606;
        border-radius: 15px;
        color: #fff;
        font-size: 20px;
        font-weight: 600;
        line-height: normal;
        text-align: center;
        text-decoration: none;
    
    }
    QPushButton:hover {
        color: #fff;
        background-color: #eb3636;
    }
        """)
        self.layout.addWidget(self.back_button, alignment=Qt.AlignCenter)

        self.spacer_bottom = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.layout.addItem(self.spacer_bottom)
        
        self.setLayout(self.layout)

    def back(self):
        self.main_window.central_widget.setCurrentWidget(self.main_window.main_menu)

    def set_username(self, username):
        self.username = username
        self.welcome_label.setText(f"Welcome {username}!")

    def show_chats(self):
        # We want to download new messages before showing the chats
        download_new_messages(self.username, self.main_window.user_menu.db)
        # Get the list of active chats
        chats = get_active_chats(self.username, self.main_window.user_menu.db.chats)
        self.main_window.chat_list_window.search_input.clear()
        self.main_window.chat_list_window.chat_list.clear()
        self.main_window.chat_list_window.set_chats(chats)
        self.main_window.central_widget.setCurrentWidget(self.main_window.chat_list_window)
        self.main_window.chat_list_window.timer.start(1000)


    def show_groups(self):
        # We want to download new messages before showing the chats
        download_new_messages(self.username, self.main_window.user_menu.db)
        # Get the list of active groups
        groups = get_active_groups(self.username, self.main_window.user_menu.db.chats)
        self.main_window.group_list_window.search_input.clear()
        self.main_window.group_list_window.group_list.clear()
        self.main_window.group_list_window.set_groups(groups)
        self.main_window.central_widget.setCurrentWidget(self.main_window.group_list_window)
        self.main_window.group_list_window.timer.start(1000)

class ChatListWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("User Menu")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(5)

        # Create a back button
        back_button = QPushButton("<- Back", self)
        back_button.setFixedSize(50, 20)
        back_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        back_button.setStyleSheet("""
        QPushButton {
            background-color: #e31717;
            border: 1px solid #c20606;
            border-radius: 10px;
            color: #fff;
            font-size: 8px;
            font-weight: 600;
            line-height: normal;
            text-align: center;
            text-decoration: none;
        }
        QPushButton:hover {
            color: #fff;
            background-color: #eb3636;
        }
        """)
        back_button.clicked.connect(self.back)
        layout.addWidget(back_button, alignment=Qt.AlignLeft)

        # Create a search bar
        search_bar = QHBoxLayout()
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Start a new chat...")
        self.search_input.textChanged.connect(self.filter_chats)
        search_bar.addWidget(self.search_input)

        contact_button = QPushButton("New Chat", self)
        contact_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        contact_button.setFixedSize(70, 40)
        contact_button.setStyleSheet("""
        QPushButton {
            background-color: #5CB7DA;
            border: 1px solid #28a4d4;
            border-radius: 10px;
            color: #fff;
            font-size: 12px;
            font-weight: 600;
            line-height: normal;
            text-align: center;
            text-decoration: none;
        
        }
        QPushButton:hover {
            color: #fff;
            background-color: #6fcaed;
        }  
        """)
        contact_button.clicked.connect(self.new_chat)
        search_bar.addWidget(contact_button)

        layout.addLayout(search_bar)

        self.chat_list = QListWidget(self)
        self.chat_list.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        layout.addWidget(self.chat_list)
    
        self.setLayout(layout)
        self.apply_style()

        # Set up a timer to fetch messages every second
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_chats)

    def apply_style(self):
        style = """
        QPushButton {
            background-color: #fcfcfc;
            border: none;
        }
        
        QLineEdit {
            padding: 10px;
            font-size: 16px;
            background-color: #f5f5f5; 
            border: 1px solid #e6e6e6; 
            border-radius: 10px;
        }
        QListWidget {
            border: none;
            font-size: 16px;
        }
        QListWidget::item {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        QListWidget::item:hover {
            background-color: #8f8f8f;
            color: white;
        }
        """
        self.setStyleSheet(style)

    def new_chat(self):
        user = self.search_input.text().strip()
        if user != self.main_window.user_menu.username:
            if user not in get_active_chats(self.main_window.user_menu.username,self.main_window.user_menu.db.chats):
                response = send_initial_message(self.main_window.user_menu.username, user, self.main_window.user_menu.db.keys, self.main_window.user_menu.db.chats,"INIT")
                if user != "" and response["code"] !=-1:
                    self.main_window.chat_window.set_chat_user(user)
                    self.main_window.chat_window.timer.start(1000)
                    self.main_window.central_widget.setCurrentWidget(self.main_window.chat_window)
                else:
                    QMessageBox.warning(self, "Error", response["error"])
            else:
                QMessageBox.warning(self, "Error", "Already existing chat")
        else:
            QMessageBox.warning(self, "Error", "You can not create a chat with yourself")

    def set_chats(self, chats):
        self.chats = chats
        self.display_chats(chats)

    def fetch_chats(self):
        download_new_messages(self.main_window.user_menu.username, self.main_window.user_menu.db)
        chats = get_active_chats(self.main_window.user_menu.username, self.main_window.user_menu.db.chats)
        self.display_chats(chats)

    def display_chats(self, chats):
        self.chat_list.clear()
        for chat in chats:
            item = QListWidgetItem(chat)
            self.chat_list.addItem(item)
        self.chat_list.itemClicked.connect(self.open_chat)

    def filter_chats(self):
        search_text = self.search_input.text().lower()
        filtered_chats = [chat for chat in self.chats if search_text in chat.lower()]
        self.display_chats(filtered_chats)

    def open_chat(self, item):
        self.timer.stop()
        chat_user = item.text()
        self.main_window.chat_window.set_chat_user(chat_user)
        self.main_window.chat_window.timer.start(1000)
        self.main_window.central_widget.setCurrentWidget(self.main_window.chat_window)
        
    
    def back(self):
        self.timer.stop()
        self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)

class ChatWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.chat_user = None
        self.chat_length = 0
        self.chat_type = "DM"
        self.chat_color = None
        self.init_ui()

    def set_chat_user(self, chat_user, chat_type="DM"):
        self.chat_user = chat_user
        self.chat_type = chat_type
        self.chat_color = random.choice(COLORS)
        self.chat_length = 0
        self.chat_display.clear()
        self.setWindowTitle(self.chat_user)
        self.user_label.setText(self.chat_user)
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 5, 0, 5)
        # Top bar with the username of the chat user
        top_bar = QHBoxLayout()
        back_button = QPushButton("<- Back", self)
        back_button.setFixedSize(50, 20)
        back_button.setStyleSheet("""
        QPushButton {
            background-color: #e31717;
            border: 1px solid #c20606;
            border-radius: 10px;
            color: #fff;
            font-size: 8px;
            font-weight: 600;
            line-height: normal;
            text-align: center;
            text-decoration: none;
            margin-left: 5px;
        }
        QPushButton:hover {
            color: #fff;
            background-color: #eb3636;
        }
        """)
        back_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        back_button.clicked.connect(self.go_back)
        top_bar.addWidget(back_button, alignment=Qt.AlignLeft)

        self.user_label = QLabel(self.chat_user, self)
        self.user_label.setAlignment(Qt.AlignCenter)
        top_bar.addWidget(self.user_label)
        
        top_bar.addStretch()
        layout.addLayout(top_bar)

        # Chat display area
        self.chat_display = QTextEdit(self)
        self.chat_display.setReadOnly(True)
        # Set the size policy to expand horizontally and vertically
        self.chat_display.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.chat_display.setStyleSheet("background-color: #f5f5f5; border: none;")
        layout.addWidget(self.chat_display)

        # Message input area
        bottom_bar = QHBoxLayout()
        bottom_bar.setSpacing(0)
        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText("Type your message here...")
        bottom_bar.addWidget(self.message_input)
        
        send_button = QPushButton("Send", self)
        send_button.clicked.connect(self.send_message)
        send_button.setFixedSize(70, 42)
        send_button.setStyleSheet(
        "color: white; background-color: #5CB7DA; border: 2px solid #28a4d4; border-top-right-radius: 15px; border-bottom-right-radius: 15px; margin-right: 5px; font-size: 16px; font-weight: bold;")
        
        bottom_bar.addWidget(send_button)
        
        layout.addLayout(bottom_bar)
        
        self.setLayout(layout)
        self.apply_style()

        # Set up a timer to fetch messages every second
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_messages)
    
    def fetch_messages(self):
        download_new_messages(self.main_window.user_menu.username, self.main_window.user_menu.db)
        if self.chat_type == "DM":
            messages = load_chat(self.main_window.user_menu.username, self.chat_user, self.main_window.user_menu.db.chats)
        else:
            messages = load_group(self.chat_user ,self.main_window.user_menu.db.chats)
        
        if len(messages) > self.chat_length:
            self.chat_display.clear()
            for message in messages:
                message = decrypt_message(message, self.main_window.user_menu.username, self.chat_user, self.main_window.user_menu.db.keys)
                self.add_message(message["sender"], message["message"].decode(), message["timestamp"])
            self.chat_length = len(messages)

    def apply_style(self):
        style = """
        QLabel {
            font-size: 18px;
            font-weight: bold;
        }
        QTextEdit {
            background-color: #F0F0F0;
            padding: 10px;
            font-size: 16px;
        }
        QLineEdit {
            padding: 10px;
            font-size: 16px;
            border-top-left-radius: 15px;
            border-bottom-left-radius: 15px;
            border: 1px solid #1A1A1A;
            margin-left: 5px;
        }
        QPushButton:hover {
            background-color: #3B3B3B;
        }
        """
        self.setStyleSheet(style)

    def send_message(self):
        message = self.message_input.text().strip()
        if message:
            send_message(bytes(message, 'utf-8'),self.main_window.user_menu.username, self.chat_user, self.main_window.user_menu.db.chats, self.main_window.user_menu.db.keys)
            self.add_message(self.main_window.user_menu.username, message, time.time())
            self.message_input.clear()

    def add_message(self, sender, message, timestamp):
        if sender == self.main_window.user_menu.username:
            alignment = Qt.AlignRight
        else:
            alignment = Qt.AlignLeft
        
        timestamp_obj = datetime.fromtimestamp(timestamp)
        # Formattare il timestamp
        formatted_timestamp = timestamp_obj.strftime('%Y-%m-%d %H:%M')
        self.chat_display.append(f"<p style='color: {self.chat_color};'><b>{sender}:</b>&nbsp;<span style = 'color: black;'>{message}</span>&nbsp;"
                                 f"<span style='float: right; font-size: 10px; color: gray;'>{formatted_timestamp}</span></p>")

    def go_back(self):
        self.timer.stop()
        self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)
        




class GroupListWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("User Menu")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(5)

        # Create a back button
        back_button = QPushButton("<- Back", self)
        back_button.setFixedSize(50, 20)
        back_button.setStyleSheet("""
        QPushButton {
            background-color: #e31717;
            border: 1px solid #c20606;
            border-radius: 10px;
            color: #fff;
            font-size: 8px;
            font-weight: 600;
            line-height: normal;
            text-align: center;
            text-decoration: none;
        }
        QPushButton:hover {
            color: #fff;
            background-color: #eb3636;
        }
        """)
        back_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        back_button.clicked.connect(self.back)
        layout.addWidget(back_button, alignment=Qt.AlignLeft)

        # Create a search bar
        search_bar = QHBoxLayout()
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Start a new group chat...")
        search_bar.addWidget(self.search_input)

        contact_button = QPushButton("New Group", self)
        contact_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        contact_button.setFixedSize(70, 40)
        contact_button.setStyleSheet("""
        QPushButton {
            background-color: #5CB7DA;
            border: 1px solid #28a4d4;
            border-radius: 10px;
            color: #fff;
            font-size: 12px;
            font-weight: 600;
            line-height: normal;
            text-align: center;
            text-decoration: none;
        
        }
        QPushButton:hover {
            color: #fff;
            background-color: #6fcaed;
        }  
        """)
        contact_button.clicked.connect(self.new_group)
        search_bar.addWidget(contact_button)

        layout.addLayout(search_bar)

        self.group_list = QListWidget(self)
        self.group_list.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        layout.addWidget(self.group_list)
        
    
        self.setLayout(layout)
        self.apply_style()

        # Set up a timer to fetch messages every second
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_groups)
        self.timer.timeout.connect(self.fetch_groups)

    def apply_style(self):
        style = """
        QPushButton {
            background-color: #fcfcfc;
            border: none;
        }
        
        QLineEdit {
            padding: 10px;
            font-size: 16px;
            background-color: #f5f5f5; 
            border: 1px solid #e6e6e6; 
            border-radius: 10px;
        }
        QListWidget {
            border: none;
            font-size: 16px;
        }
        QListWidget::item {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        QListWidget::item:hover {
            background-color: #8f8f8f;
            color: white;
        }
        """
        self.setStyleSheet(style)

    def new_group(self):
        group_name = self.search_input.text().strip()
        if group_name != "":
            if check_group(group_name) != True:
                dialog = AddUserDialog(self.main_window.user_menu.username ,group_name, self.main_window.user_menu.db)
                dialog.exec_()
            else:
                QMessageBox.warning(self, "Error", "Group name already in use!", QMessageBox.Ok)
        """
        user = self.search_input.text().strip()
        if user != "":
            send_initial_message(self.main_window.user_menu.username, user, self.main_window.user_menu.db.keys, self.main_window.user_menu.db.chats)
            self.main_window.chat_window.set_chat_user(user)
            self.main_window.chat_window.timer.start(1000)
            self.main_window.central_widget.setCurrentWidget(self.main_window.chat_window)
        """
    def set_groups(self, groups):
        self.groups = groups
        self.display_groups(groups)

    def fetch_groups(self):
        download_new_messages(self.main_window.user_menu.username, self.main_window.user_menu.db)
        groups = list(get_active_groups(self.main_window.user_menu.username,self.main_window.user_menu.db.chats))
        self.display_groups(groups)

    def display_groups(self, groups):
        self.group_list.clear()
        for group in groups:
            item = QListWidgetItem(group)
            self.group_list.addItem(item)
        self.group_list.itemClicked.connect(self.open_group)

    def filter_groups(self):
        search_text = self.search_input.text().lower()
        filtered_groups = [group for group in self.groups if search_text in group.lower()]
        self.display_groups(filtered_groups)

    def open_group(self, item):
        self.timer.stop()
        chat_user = item.text()
        self.main_window.chat_window.set_chat_user(chat_user, "GROUP")
        self.main_window.chat_window.timer.start(1000)
        self.main_window.central_widget.setCurrentWidget(self.main_window.chat_window)
        
    
    def back(self):
        self.timer.stop()
        self.main_window.central_widget.setCurrentWidget(self.main_window.user_menu)

class AddUserDialog(QDialog):
    def __init__(self, username, group_name, db):
        super().__init__()
        self.group_name = group_name
        self.username = username
        self.db = db
        self.group_key = secrets.token_bytes(32)
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('Add Users')

        # Layout principale
        layout = QVBoxLayout()
        
        # Etichetta con il testo
        self.label = QLabel(f"Add users to group '{self.group_name}'")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)
        
        # Layout per il campo di input e il pulsante Add
        input_layout = QHBoxLayout()
        self.user_input = QLineEdit(self)
        input_layout.addWidget(self.user_input)
        
        self.add_button = QPushButton('Add', self)
        input_layout.addWidget(self.add_button)
        layout.addLayout(input_layout)
        
        # Pulsante End
        self.end_button = QPushButton('End', self)
        layout.addWidget(self.end_button)
        
        # Centra tutto il contenuto
        layout.setAlignment(self.label, Qt.AlignCenter)
        layout.setAlignment(input_layout, Qt.AlignCenter)
        layout.setAlignment(self.end_button, Qt.AlignCenter)
        
        self.setLayout(layout)
        
        self.add_button.clicked.connect(self.add_user)
        self.end_button.clicked.connect(self.close)

    def closeDialog(self):
        self.close()


    def add_user(self):
        new_member = self.user_input.text()
        response = send_initial_message(self.username, new_member, self.db.keys, self.db.chats, 'INIT_GROUP', self.group_key, self.group_name)
        if new_member != "" and response["code"] !=-1:
            print(f"User '{new_member}' added to group '{self.group_name}'")
        else:
            QMessageBox.warning(self, "Error", response["error"])
        self.user_input.clear()
      


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
