from PyQt5.QtWidgets import QMainWindow, QApplication, QVBoxLayout, QPushButton
from cryptography.fernet import Fernet
from PyQt5 import QtWidgets
import sys
import json
import os
import base64

isLoggedIn = False
user = {}
file_path = "passwords.json"
key_file_path = "secret.key"

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUi()

        #* Load Key
        if not os.path.exists(key_file_path):
            self.generate_key()
        self.cipher = Fernet(self.load_key())

        #* Connect Button
        self.button_submit.clicked.connect(self.submit_pressed)

        #* Load users
        try:
            with open(file_path, "r") as file:
                global user
                user = json.load(file)
        except FileNotFoundError:
            print("File not found. Initializing new one")
            user = {}
        except json.JSONDecodeError:
            print("Error decoding JSON. Initializing new one.")
            user = {}

    def initUi(self):
        #* GUI components
        self.textfield_username = QtWidgets.QLineEdit(self)
        self.label_username_info = QtWidgets.QLabel("Enter Username:", self)
        self.textfield_password = QtWidgets.QLineEdit(self)
        self.label_password_info = QtWidgets.QLabel("Enter Password:", self)
        self.label_info = QtWidgets.QLabel("", self)
        self.button_submit = QPushButton("Create Account/Log in", self)
        self.textfield_username.setMinimumSize(200, 100)
        self.textfield_password.setMinimumSize(200, 100)
        self.button_submit.setMinimumSize(200, 50)
        self.label_username_info.setMinimumSize(200, 50)
        self.label_password_info.setMinimumSize(200, 50)
        self.label_info.setMinimumSize(200, 50)

        #* Layout management
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(self.label_info)
        layout.addWidget(self.label_username_info)
        layout.addWidget(self.textfield_username)
        layout.addWidget(self.label_password_info)
        layout.addWidget(self.textfield_password)
        layout.addWidget(self.button_submit)
        central_widget.setLayout(layout)

        #* Main Frame
        self.setWindowTitle("Password Manager")
        self.setGeometry(700, 300, 500, 500)

        #* Style management
        self.setStyleSheet("""
            QLabel { 
                font-size: 30px;
                font-family: "Times New Roman";
            }
            QPushButton {  
                border: 1px solid;
                border-radius: 15px;
            } 
            QLineEdit {
                border: 1px solid;
                border-radius: 15px;
                font-size: 35px;
                font-family: "Times New Roman";
            }             
                           """)

    def submit_pressed(self):
        if not isLoggedIn:
            password = self.textfield_password.text().strip()
            username = self.textfield_username.text().strip()
            #* Checks if fields are filled
            if(password == "" and username == ""):
                self.label_info.setText("Must enter username and password!")
            #* Checks if password is entered
            elif(password == ""):
                self.label_info.setText("Must enter password!")
            #* Checks if username is entered
            elif(username == ""):
                self.label_info.setText("Must enter username!")
            else:
                #* Checks if user already exists and password is correct
                if self.check_user(username):
                    if self.check_password(username, password):
                        self.login()                    
                    else:
                        self.label_info.setText("Incorrect password!")  
                #* If not, creates a new user
                else:
                    self.create_account()
        else:
            self.logout()            
    
    def create_account(self):
        with open(file_path, "w") as file:
            #* creates a new user
            username = self.textfield_username.text().strip()
            password = self.encrypt(self.textfield_password.text().strip())
            #* Encrypts and stores the password
            user[username] = base64.urlsafe_b64encode(password).decode()
            json.dump(user, file, indent=4)
            self.label_info.setText("Account created successfully!")

    def check_password(self, username, password):
        #* checks if password is correct 
        stored_password = self.decrypt(user[username])
        return stored_password == password

    
    def check_user(self, username):
        #* checks if user exists or not
        if username in user:
            return True
        return False

    def login(self):
        self.label_info.setText("You're logged in successfully")
        global isLoggedIn
        isLoggedIn = True
        #* Change UI
        self.label_password_info.hide()
        self.textfield_password.hide()
        self.label_username_info.hide()
        self.textfield_username.hide()
        self.button_submit.setText("Logout")

    def logout(self):
        self.label_info.setText("You logged out successfully")
        global isLoggedIn
        isLoggedIn = False
        #* Change UI
        self.label_password_info.show()
        self.textfield_password.show()
        self.label_username_info.show()
        self.textfield_username.show()
        self.button_submit.setText("Create Account/Log in")

    def encrypt(self, password):
        #* Encrypts the password
        return self.cipher.encrypt(password.encode())

    def decrypt(self, password):
        #* Decrypts the password
        return self.cipher.decrypt(base64.urlsafe_b64decode(password)).decode()
    
    def load_key(self):
        return open(key_file_path, 'rb').read()

    def generate_key(self):
        key = Fernet.generate_key()
        with open(key_file_path, "wb") as key_file:
            key_file.write(key)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
