#!/usr/bin/python3
import tkinter as tk
import tkinter.ttk as ttk
from wdc_crypto import *

class Menu:
    def __init__(self, master):
        # build ui
        self.master = master
        self.menu6 = tk.Menu(master)
        self.menu_file = tk.Menu(self.menu6)
        self.menu6.add(tk.CASCADE, menu=self.menu_file, label="File")
        self.mi_menu_exit = 1
        self.menu_file.add("command", label="Exit")
        self.menu_file.entryconfigure(self.mi_menu_exit, command=self.exit)
        self.menu_help = tk.Menu(self.menu6)
        self.menu6.add(tk.CASCADE, menu=self.menu_help, label="Help")

    def exit(self):
        self.master.destroy()

class CryptoGUI:
    def __init__(self, master=None):
        # build ui
        self.top_level = tk.Tk() if master is None else tk.Toplevel(master)
        self.menu = Menu(master=self.top_level)
        self.top_level.config(menu=self.menu.menu6)
        self.main_frame = ttk.Frame(self.top_level)
        self.notebook = ttk.Notebook(self.main_frame)
        self.frame_4 = ttk.Frame(self.notebook)
        self.label_2 = ttk.Label(self.frame_4)
        self.label_2.configure(text="Wybierz algorytm")
        self.label_2.grid(column="0", padx="5", pady="5", row="0")
        self.generateComboBox = ttk.Combobox(self.frame_4, values=AssymetricKeyType._member_names_)
        self.generateComboBox.configure(state="readonly")
        self.generateComboBox.grid(column="0", padx="5", pady="5", row="1")
        self.generateComboBox.current(0)
        self.private_key_entry = ttk.Entry(self.frame_4)
        self.private_key = tk.StringVar(value="")
        self.private_key_entry.configure(
            state="readonly", textvariable=self.private_key
        )
        self.private_key_entry.grid(column="0", ipadx="5", padx="0", pady="5", row="3")
        self.public_key_entry = ttk.Entry(self.frame_4)
        self.public_key = tk.StringVar(value="")
        self.public_key_entry.configure(state="readonly", textvariable=self.public_key)
        self.public_key_entry.grid(column="0", ipadx="5", pady="5", row="4")
        self.label_5 = ttk.Label(self.frame_4)
        self.label_5.configure(text="Klucz prywatny")
        self.label_5.grid(column="1", padx="5", row="3")
        self.label_6 = ttk.Label(self.frame_4)
        self.label_6.configure(text="Klucz publiczny")
        self.label_6.grid(column="1", row="4")
        self.frame_1 = ttk.Frame(self.frame_4)
        self.button_3 = ttk.Button(self.frame_1)
        self.button_3.configure(text="Generuj klucze")
        self.button_3.grid(column="0", row="0")
        self.button_3.configure(command=self.generateKeys)
        self.button_4 = ttk.Button(self.frame_1)
        self.button_4.configure(text="Zapisz klucze")
        self.button_4.grid(column="1", padx="5", row="0")
        self.button_4.configure(command=self.saveKeys)
        self.frame_1.configure(height="100")
        self.frame_1.grid(column="0", padx="5", pady="5", row="5", sticky="w")
        self.keyLengthComboBox = ttk.Combobox(self.frame_4, values=[16,32,64,128,256,512,1024])
        self.keyLengthComboBox.configure(state="readonly")
        self.keyLengthComboBox.grid(column="0", row="2")
        self.keyLengthComboBox.current(2)
        self.frame_4.configure(height="200", width="200")
        self.frame_4.pack(side="top")
        self.notebook.add(self.frame_4, text="Generowanie kluczy")
        self.frame_5 = ttk.Frame(self.notebook)
        self.frame_5.configure(height="200", width="200")
        self.frame_5.pack(side="top")
        self.notebook.add(self.frame_5, text="Szyfrowanie")
        self.frame_6 = ttk.Frame(self.notebook)
        self.frame_6.configure(height="200", width="200")
        self.frame_6.pack(side="top")
        self.notebook.add(self.frame_6, text="Deszyfrowanie")
        self.notebook.configure(height="200", width="200")
        self.notebook.pack(expand="true", fill="both", side="top")
        self.main_frame.configure(height="200", width="200")
        self.main_frame.pack(expand="true", fill="both", side="top")
        self.top_level.configure(height="480", takefocus=False, width="640")
        self.top_level.geometry("640x480")

        # Main widget
        self.mainwindow = self.top_level

    def run(self):
        self.mainwindow.mainloop()

    def generateKeys(self):
        algorithm = self.generateComboBox.get()
        length = int(self.keyLengthComboBox.get())
        private, public = generateKeys(AssymetricKeyType[algorithm], length)
        self.private_key.set(value=private.key)
        self.public_key.set(public.key)


    def saveKeys(self):
        pass