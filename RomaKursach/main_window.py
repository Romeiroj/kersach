# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(864, 596)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(864, 596))
        MainWindow.setMaximumSize(QtCore.QSize(864, 596))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(690, 10, 162, 111))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.NPN = QtWidgets.QCheckBox(self.verticalLayoutWidget)
        self.NPN.setObjectName("NPN")
        self.verticalLayout.addWidget(self.NPN)
        self.PN = QtWidgets.QCheckBox(self.verticalLayoutWidget)
        self.PN.setObjectName("PN")
        self.verticalLayout.addWidget(self.PN)
        self.RPN = QtWidgets.QCheckBox(self.verticalLayoutWidget)
        self.RPN.setObjectName("RPN")
        self.verticalLayout.addWidget(self.RPN)
        self.input_lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.input_lineEdit.setGeometry(QtCore.QRect(20, 80, 641, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.input_lineEdit.setFont(font)
        self.input_lineEdit.setObjectName("input_lineEdit")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(20, 10, 641, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setStyleStrategy(QtGui.QFont.PreferDefault)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(20, 40, 641, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.error_label = QtWidgets.QLabel(self.centralwidget)
        self.error_label.setGeometry(QtCore.QRect(20, 130, 461, 51))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.error_label.setFont(font)
        self.error_label.setText("")
        self.error_label.setObjectName("error_label")
        self.plainTextEdit = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit.setGeometry(QtCore.QRect(13, 200, 781, 361))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.plainTextEdit.setFont(font)
        self.plainTextEdit.setReadOnly(True)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.calculateButton = QtWidgets.QPushButton(self.centralwidget)
        self.calculateButton.setGeometry(QtCore.QRect(690, 130, 161, 31))
        self.calculateButton.setObjectName("calculateButton")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Польская запись"))
        self.NPN.setText(_translate("MainWindow", "Обычный пример"))
        self.PN.setText(_translate("MainWindow", "Польская запись"))
        self.RPN.setText(_translate("MainWindow", "Обратная польская запись"))
        self.input_lineEdit.setPlaceholderText(_translate("MainWindow", "Введите пример с пробелами после каждого знака"))
        self.label.setText(_translate("MainWindow", "Чтобы воспользоваться этим калькулятором: выберите какой тип примера вы введёте, введите этот"))
        self.label_2.setText(_translate("MainWindow", "пример в строку ниже и нажмите кнопку \"Подсчёт\"."))
        self.calculateButton.setText(_translate("MainWindow", "Подсчёт"))