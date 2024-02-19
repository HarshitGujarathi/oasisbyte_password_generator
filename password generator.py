import random
import string
import tkinter as tk
from tkinter import ttk
import pyperclip

def generatepassword(length, lowercase=True, uppercase=True, numbers=True, symbols=True):
    

    # Validate user input
    if length <= 0:
        raise ValueError("Password length must be positive.")

    char_set = ""
    if lowercase:
        char_set += string.ascii_lowercase
    if uppercase:
        char_set += string.ascii_uppercase
    if numbers:
        char_set += string.digits
    if symbols:
        char_set += string.punctuation

    if not char_set:
        raise ValueError("At least one character type must be selected.")

    # Generate random password
    password = ''.join(random.choice(char_set) for _ in range(length))
    return password

def display_password():
    try:
        password_length = int(length_var.get())
        lowercase_var = lowercase_chk_var.get()
        uppercase_var = uppercase_chk_var.get()
        numbers_var = numbers_chk_var.get()
        symbols_var = symbols_chk_var.get()

        password = generatepassword(password_length, lowercase_var, uppercase_var, numbers_var, symbols_var)

        result_var.set(password)
        pyperclip.copy(password)  # Copy to clipboard
    except ValueError:
        result_var.set("Invalid input. Please try again.")

# GUI Setup
root = tk.Tk()
root.title("Password Generator")

# Password Length
length_label = ttk.Label(root, text="Password Length:")
length_label.grid(row=0, column=0, padx=5, pady=5)
length_var = tk.StringVar(value="12")
length_entry = ttk.Entry(root, textvariable=length_var)
length_entry.grid(row=0, column=1, padx=5, pady=5)

# Character Type Checkboxes
lowercase_chk_var = tk.BooleanVar(value=True)
lowercase_chk = ttk.Checkbutton(root, text="Lowercase", variable=lowercase_chk_var)
lowercase_chk.grid(row=1, column=0, padx=5, pady=5, sticky="W")

uppercase_chk_var = tk.BooleanVar(value=True)
uppercase_chk = ttk.Checkbutton(root, text="Uppercase", variable=uppercase_chk_var)
uppercase_chk.grid(row=1, column=1, padx=5, pady=5, sticky="W")

numbers_chk_var = tk.BooleanVar(value=True)
numbers_chk = ttk.Checkbutton(root, text="Numbers", variable=numbers_chk_var)
numbers_chk.grid(row=2, column=0, padx=5, pady=5, sticky="W")

symbols_chk_var = tk.BooleanVar(value=True)
symbols_chk = ttk.Checkbutton(root, text="Symbols", variable=symbols_chk_var)
symbols_chk.grid(row=2, column=1, padx=5, pady=5, sticky="W")

# Generate Button
generate_btn = ttk.Button(root, text="Generate Password", command=display_password)
generate_btn.grid(row=3, column=0, columnspan=2, pady=10)

# Display Result
result_var = tk.StringVar()
result_label = ttk.Label(root, textvariable=result_var, font=("Helvetica", 12))
result_label.grid(row=4, column=0, columnspan=2, padx=5, pady=10)

# Run the GUI
root.mainloop()
