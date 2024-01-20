import re
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
from login_window import Ui_LoginForm
from main_window import Ui_MainWindow
import sqlite3
import bcrypt


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.calculateButton.clicked.connect(self.calculation)

    def calculation(self):
        selected_count = 0
        type_of_calculation = ''

        if self.NPN.isChecked():
            selected_count += 1
            type_of_calculation = "NPN"

        if self.PN.isChecked():
            selected_count += 1
            type_of_calculation = "PN"

        if self.RPN.isChecked():
            selected_count += 1
            type_of_calculation = "RPN"

        if selected_count == 0:
            self.error_label.setText("Выберите тип примера")

        elif selected_count > 1:
            self.error_label.setText("Выберите только один тип примера")

        else:
            self.error_label.clear()

            if type_of_calculation == "NPN":
                pn_convertor_result = pn_convertor(str(self.input_lineEdit.text()))
                result = pn_deconvertor(pn_convertor_result)
                rpn_convertor_result = rpn_convertor(str(self.input_lineEdit.text()))

                if result:
                    self.plainTextEdit.appendPlainText(f"Пример в польской записи: {pn_convertor_result}\n")
                    self.plainTextEdit.appendPlainText(f"Пример в обратной польской записи: {rpn_convertor_result}\n")
                    self.plainTextEdit.appendPlainText(f"Ответ: {result[0]}\n")
                else:
                    self.error_label.setText("Не правильно введен пример или неправильно указан его тип")

            elif type_of_calculation == "PN":
                result = pn_deconvertor(str(self.input_lineEdit.text()))

                if result:
                    self.plainTextEdit.appendPlainText(f"Ответ: {result[0]}\n")
                else:
                    self.error_label.setText("Не правильно введен пример или неправильно указан его тип")

            elif type_of_calculation == "RPN":
                result = rpn_deconvertor(str(self.input_lineEdit.text()))

                if result:
                    self.plainTextEdit.appendPlainText(f"Ответ: {result[0]}\n")
                else:
                    self.error_label.setText("Не правильно введен пример или неправильно указан его тип")


class LoginForm(QMainWindow, Ui_LoginForm):
    def __init__(self):
        super().__init__()
        self.main_window = None
        self.setupUi(self)

        self.login.clicked.connect(self.login_clicked)
        self.registration.clicked.connect(self.registration_clicked)

    def open_main_window(self):
        self.main_window = MainWindow()
        self.main_window.show()

    def login_clicked(self):
        username = self.loginEdit.text()
        password = self.passwordEdit.text()

        if not username or not password:
            self.label.setText("Введите логин и пароль для входа")
        else:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()

            cursor.execute("SELECT password FROM users WHERE username=?", (username,))
            user_data = cursor.fetchone()
            conn.close()

            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[0]):
                self.close()
                self.open_main_window()
            else:
                self.label.setText("Не верно введен логин или пароль")
                self.passwordEdit.clear()

    def registration_clicked(self):
        username = self.loginEdit.text()
        password = self.passwordEdit.text()

        if not username or not password:
            self.label.setText("Введите логин и пароль для создания нового аккаунта")
        else:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                self.label.setText("Пользователь с таким логином уже существует")
            else:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                conn.close()

                self.label.setText("Новый аккаунт успешно создан")

            self.loginEdit.clear()
            self.passwordEdit.clear()


def pn_convertor(input_line):

    def simple_convertor_pn(simple_line):
        sign_array = ['+', '-', '*', '/', '^']
        polish = ''

        for operator in sign_array:
            operator_position = simple_line.rfind(operator)

            if operator_position >= 0:
                polish = f"{operator} {simple_convertor_pn(simple_line[:operator_position].strip())} {simple_convertor_pn(simple_line[operator_position + 1:].strip())}"
                break

        if not polish:
            polish = simple_line

        return polish

    temp_formula = input_line
    bracket_found = True
    i = 0
    alias_replacements = {}

    try:
        while bracket_found:
            open_bracket = temp_formula.rfind('(')

            if open_bracket >= 0:
                close_bracket = temp_formula.find(')', open_bracket)
                i += 1
                alias_replacement = f'#{i}'
                alias_replacements[alias_replacement] = simple_convertor_pn(temp_formula[open_bracket + 1:close_bracket].strip())
                temp_formula = f"{temp_formula[:open_bracket].strip()} {alias_replacement} {temp_formula[close_bracket + 1:].strip()}"
            else:
                bracket_found = False

        simple_formula = simple_convertor_pn(temp_formula)

        while i > 0:
            alias_replacement = f'#{i}'
            i -= 1
            simple_formula = simple_formula.replace(alias_replacement, alias_replacements[alias_replacement])
    except:
        return []

    return simple_formula


def pn_deconvertor(input_line):
    input_line = input_line.split(" ")
    pattern = r'^[-]?[0-9]*[.]?[0-9]+$'
    temp = []
    i = 0

    try:
        while len(input_line) > 1:
            match = re.match(pattern, input_line[i])
            if match:
                try:

                    temp.clear()
                    temp.append(float(input_line[i]))
                    temp.append(float(input_line[i + 1]))

                    if input_line[i-1] == '+':
                        intermediate_calculation = temp[0] + temp[1]
                    elif input_line[i-1] == '-':
                        intermediate_calculation = temp[0] - temp[1]
                    elif input_line[i-1] == '*':
                        intermediate_calculation = temp[0] * temp[1]
                    elif input_line[i-1] == '/':
                        intermediate_calculation = temp[0] / temp[1]
                    elif input_line[i-1] == '^':
                        intermediate_calculation = temp[0] ** temp[1]
                    else:
                        raise ValueError("Недопустимый оператор")

                    input_line.pop(i - 1)
                    input_line.pop(i - 1)
                    input_line.pop(i - 1)
                    input_line.insert(i-1, str(intermediate_calculation))

                    i -= 2
                except ValueError:
                    i += 1
            else:
                i += 1
    except:
        return []

    return input_line


def rpn_convertor(input_line):

    def simple_convertor_rpn(simple_line):
        sign_array = ['+', '-', '*', '/', '^']
        polish = ''

        for operator in sign_array:
            operator_position = simple_line.rfind(operator)

            if operator_position >= 0:
                polish = f"{simple_convertor_rpn(simple_line[:operator_position].strip())} {simple_convertor_rpn(simple_line[operator_position + 1:].strip())} {operator}"
                break

        if not polish:
            polish = simple_line

        return polish

    temp_formula = input_line
    bracket_found = True
    i = 0
    alias_replacements = {}

    try:
        while bracket_found:
            open_bracket = temp_formula.rfind('(')

            if open_bracket >= 0:
                close_bracket = temp_formula.find(')', open_bracket)
                i += 1
                alias_replacement = f'#{i}'
                alias_replacements[alias_replacement] = simple_convertor_rpn(temp_formula[open_bracket + 1:close_bracket].strip())
                temp_formula = f"{temp_formula[:open_bracket].strip()} {alias_replacement} {temp_formula[close_bracket + 1:].strip()}"
            else:
                bracket_found = False

        simple_formula = simple_convertor_rpn(temp_formula)

        while i > 0:
            alias_replacement = f'#{i}'
            i -= 1
            simple_formula = simple_formula.replace(alias_replacement, alias_replacements[alias_replacement])
    except:
        return []

    return simple_formula


def rpn_deconvertor(input_line):
    input_line = input_line.split(" ")
    pattern = r'^[-]?[0-9]*[.]?[0-9]+$'
    stack = []

    try:
        for token in input_line:
            match = re.match(pattern, token)
            if match:
                stack.append(float(token))
            else:
                operand2 = stack.pop()
                operand1 = stack.pop()

                if token == '+':
                    intermediate_calculation = operand1 + operand2
                elif token == '-':
                    intermediate_calculation = operand1 - operand2
                elif token == '*':
                    intermediate_calculation = operand1 * operand2
                elif token == '/':
                    intermediate_calculation = operand1 / operand2
                elif token == '^':
                    intermediate_calculation = operand1 ** operand2
                else:
                    raise ValueError("Недопустимый оператор")

                stack.append(intermediate_calculation)
    except:
        return []

    return stack


if __name__ == '__main__':
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT NOT NULL,
                          password TEXT NOT NULL)''')

    conn.commit()
    conn.close()

    app = QApplication(sys.argv)
    window = LoginForm()
    window.show()
    sys.exit(app.exec_())
