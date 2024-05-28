import customtkinter
from tkinter import filedialog
from math import gcd

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root = customtkinter.CTk()
root.geometry("500x500")
root.title("Cryptography System")

def convert_key_to_matrix(key):
    key = key.upper()
    if not key.isalpha():
        return None
    key_length = len(key)
    matrix_size = int(key_length ** 0.5)
    if matrix_size * matrix_size != key_length:
        return None
    key_matrix = [[0 for _ in range(matrix_size)] for _ in range(matrix_size)]
    index = 0
    for i in range(matrix_size):
        for j in range(matrix_size):
            key_matrix[i][j] = ord(key[index]) - ord('A')
            index += 1
    return key_matrix

def convert_key_to_numbers(key):
    key = key.upper()
    if not key.isalpha():
        return None
    return [ord(char) - ord('A') + 1 for char in key]

def clear_frame():
    for widget in frame.winfo_children():
        widget.destroy()

def open_home_scene():
    clear_frame()
    label1 = customtkinter.CTkLabel(master=frame, text="Cryptography Algorithms", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)

    label2 = customtkinter.CTkLabel(master=frame, text="Choose An Algorithm", font=("Roboto", 18))
    label2.grid(row=1, column=0, columnspan=2, pady=12, padx=10)

    button1 = customtkinter.CTkButton(master=frame, text="Transposition Row Cipher", command=open_transposition_scene)
    button1.grid(row=2, column=0, pady=12, padx=10)

    button2 = customtkinter.CTkButton(master=frame, text="Rot13", command=open_rot13_scene)
    button2.grid(row=2, column=1, pady=12, padx=10)

    button6 = customtkinter.CTkButton(master=frame, text="Caesar Cipher", command=open_caesar_scene)
    button6.grid(row=4, column=1, pady=12, padx=10)

    button3 = customtkinter.CTkButton(master=frame, text="Substitution Cipher", command=open_substitution_scene)
    button3.grid(row=4, column=0, pady=12, padx=10)

    button4 = customtkinter.CTkButton(master=frame, text="Hill Cipher", command=open_hill_scene)
    button4.grid(row=6, column=0, pady=12, padx=10)

    button5 = customtkinter.CTkButton(master=frame, text="Affine Cipher", command=open_affine_scene)
    button5.grid(row=6, column=1, pady=12, padx=10)

    button7 = customtkinter.CTkButton(master=frame, text="Affine Cipher", command=open_affine_scene)
    button7.grid(row=6, column=1, pady=12, padx=10)

def open_hill_scene():
    clear_frame()
    label1 = customtkinter.CTkLabel(master=frame, text="Hill Cipher", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)
    message_label = customtkinter.CTkLabel(master=frame, text="Message:", font=("Roboto", 12))
    message_label.grid(row=2, column=0, pady=5, padx=10)
    message_entry = customtkinter.CTkEntry(master=frame)
    message_entry.grid(row=2, column=1, pady=5, padx=10)

    key_label = customtkinter.CTkLabel(master=frame, text="Key:", font=("Roboto", 12))
    key_label.grid(row=4, column=0, pady=5, padx=10)
    key_entry = customtkinter.CTkEntry(master=frame)
    key_entry.grid(row=4, column=1, pady=5, padx=10)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 12))
    result_label.grid(row=3, column=0, pady=5, padx=10)
    result = customtkinter.CTkEntry(master=frame)
    result.grid(row=3, column=1, pady=5, padx=10)

    encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=lambda: result.insert(0, encrypt_hill(message_entry.get(), key_entry.get())))
    encrypt_button.grid(row=5, column=0, pady=5, padx=10)

    decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=lambda: result.insert(0, decrypt_hill(message_entry.get(), key_entry.get())))
    decrypt_button.grid(row=5, column=1, pady=5, padx=10)

    upload_button = customtkinter.CTkButton(master=frame, text="Upload File", command=lambda: upload_file_hill(message_entry))
    upload_button.grid(row=6, column=0, columnspan=2, pady=5, padx=10)

    download_button = customtkinter.CTkButton(master=frame, text="Download File", command=lambda: download_file(result.get()))
    download_button.grid(row=7, column=0, columnspan=2, pady=5, padx=10)

    home_button = customtkinter.CTkButton(master=frame, text="Home", command=open_home_scene)
    home_button.grid(row=8, column=0, columnspan=2, pady=5, padx=10)
def encrypt_hill(message, key):
    key_matrix = convert_key_to_matrix(key)
    if key_matrix is None:
        return "Error: Key must be a square matrix of letters."
    while len(message) % len(key_matrix) != 0:
        message += 'X'
    message_matrix = [[ord(char) - ord('A') for char in message.upper()]]
    message_matrix = [message_matrix[0][i:i + len(key_matrix)] for i in
                      range(0, len(message_matrix[0]), len(key_matrix))]

    encrypted_matrix = []
    for row in message_matrix:
        encrypted_row = []
        for i in range(len(key_matrix)):
            sum_val = 0
            for j in range(len(key_matrix)):
                sum_val += row[j] * key_matrix[i][j]
            encrypted_row.append(sum_val % 26)
        encrypted_matrix.append(encrypted_row)

    encrypted_message = ''.join([chr(num + ord('a')) for row in encrypted_matrix for num in row])
    return encrypted_message
def upload_file_hill(message_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, file.read())


def decrypt_hill(message, key):
    key_matrix = convert_key_to_matrix(key)
    if key_matrix is None:
        return "Error: Key must be a square matrix of letters."

    key_size = len(key_matrix)
    if key_size != 2 and key_size != 3:
        return "Error: Key matrix size must be 2x2 or 3x3."

    try:
        if key_size == 2:

            determinant = key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]
            det_inv = pow(determinant, -1, 26)
            key_matrix_inv = [
                [(key_matrix[1][1] * det_inv) % 26, (-key_matrix[0][1] * det_inv) % 26],
                [(-key_matrix[1][0] * det_inv) % 26, (key_matrix[0][0] * det_inv) % 26]
            ]
        else:

            determinant = key_matrix[0][0] * key_matrix[1][1] * key_matrix[2][2] + \
                          key_matrix[0][1] * key_matrix[1][2] * key_matrix[2][0] + \
                          key_matrix[0][2] * key_matrix[1][0] * key_matrix[2][1] - \
                          key_matrix[0][2] * key_matrix[1][1] * key_matrix[2][0] - \
                          key_matrix[0][1] * key_matrix[1][0] * key_matrix[2][2] - \
                          key_matrix[0][0] * key_matrix[1][2] * key_matrix[2][1]
            det_inv = pow(determinant, -1, 26)
            adjugate_matrix = [
                [
                    (key_matrix[1][1] * key_matrix[2][2] - key_matrix[1][2] * key_matrix[2][1]) * det_inv % 26,
                    (key_matrix[0][2] * key_matrix[2][1] - key_matrix[0][1] * key_matrix[2][2]) * det_inv % 26,
                    (key_matrix[0][1] * key_matrix[1][2] - key_matrix[0][2] * key_matrix[1][1]) * det_inv % 26
                ],
                [
                    (key_matrix[1][2] * key_matrix[2][0] - key_matrix[1][0] * key_matrix[2][2]) * det_inv % 26,
                    (key_matrix[0][0] * key_matrix[2][2] - key_matrix[0][2] * key_matrix[2][0]) * det_inv % 26,
                    (key_matrix[0][2] * key_matrix[1][0] - key_matrix[0][0] * key_matrix[1][2]) * det_inv % 26
                ],
                [
                    (key_matrix[1][0] * key_matrix[2][1] - key_matrix[1][1] * key_matrix[2][0]) * det_inv % 26,
                    (key_matrix[0][1] * key_matrix[2][0] - key_matrix[0][0] * key_matrix[2][1]) * det_inv % 26,
                    (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) * det_inv % 26
                ]
            ]
            key_matrix_inv = adjugate_matrix

    except ValueError:
        return "Error: Key is not invertible."

    message_matrix = [[ord(char) - ord('a') for char in message.lower()]]
    message_matrix = [message_matrix[0][i:i + key_size] for i in range(0, len(message_matrix[0]), key_size)]

    decrypted_matrix = []
    for row in message_matrix:
        decrypted_row = []
        for i in range(key_size):
            sum_val = 0
            for j in range(key_size):
                sum_val += row[j] * key_matrix_inv[i][j]
            decrypted_row.append(sum_val % 26)
        decrypted_matrix.append(decrypted_row)

    decrypted_message = ''.join([chr(int(num) + ord('a')) for row in decrypted_matrix for num in row])
    return decrypted_message



def open_caesar_scene():
    clear_frame()

    label1 = customtkinter.CTkLabel(master=frame, text="Caesar Cipher", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)

    message_label = customtkinter.CTkLabel(master=frame, text="Message:", font=("Roboto", 12))
    message_label.grid(row=2, column=0, pady=5, padx=10)
    message_entry = customtkinter.CTkEntry(master=frame)
    message_entry.grid(row=2, column=1, pady=5, padx=10)

    key_label = customtkinter.CTkLabel(master=frame, text="Key (single letter):", font=("Roboto", 12))
    key_label.grid(row=4, column=0, pady=5, padx=10)
    key_entry = customtkinter.CTkEntry(master=frame)
    key_entry.grid(row=4, column=1, pady=5, padx=10)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 12))
    result_label.grid(row=3, column=0, pady=5, padx=10)
    result_entry = customtkinter.CTkEntry(master=frame)
    result_entry.grid(row=3, column=1, pady=5, padx=10)

    encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=lambda: result_entry.insert(0, encrypt_caesar(message_entry.get(), key_entry.get())))
    encrypt_button.grid(row=5, column=0, pady=5, padx=10)

    decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=lambda: result_entry.insert(0, decrypt_caesar(message_entry.get(), key_entry.get())))
    decrypt_button.grid(row=5, column=1, pady=5, padx=10)

    upload_button = customtkinter.CTkButton(master=frame, text="Upload File", command=lambda: upload_file_caesar(message_entry))
    upload_button.grid(row=6, column=0, columnspan=2, pady=5, padx=10)

    download_button = customtkinter.CTkButton(master=frame, text="Download File",
                                              command=lambda: download_file(result_entry.get()))
    download_button.grid(row=7, column=0, columnspan=2, pady=5, padx=10)

    home_button = customtkinter.CTkButton(master=frame, text="Home", command=open_home_scene)
    home_button.grid(row=8, column=0, columnspan=2, pady=5, padx=10)

def encrypt_caesar(message, key):
    key = key.upper()  # Ensure key is uppercase
    if len(key) != 1 or not key.isalpha():  # Check if key is a single letter
        return "Error: Key must be a single letter."

    key_shift = ord(key) - ord('A')
    result = ''
    for char in message:
        if char.isalpha():
            shifted = ord(char) + key_shift
            if char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            elif char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def decrypt_caesar(ciphertext, key):
    key = key.upper()  # Ensure key is uppercase
    if len(key) != 1 or not key.isalpha():  # Check if key is a single letter
        return "Error: Key must be a single letter."

    key_shift = ord('A') - ord(key)  # Reverse the key shift for decryption
    result = ''
    for char in ciphertext:
        if char.isalpha():
            shifted = ord(char) + key_shift
            if char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            elif char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def upload_file_caesar(message_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, file.read())

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

def open_transposition_scene(result_entry=None):
    clear_frame()
    label1 = customtkinter.CTkLabel(master=frame, text="Transposition Cipher", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)
    message_label = customtkinter.CTkLabel(master=frame, text="Message:", font=("Roboto", 12))
    message_label.grid(row=2, column=0, pady=5, padx=10)
    message_entry = customtkinter.CTkEntry(master=frame)
    message_entry.grid(row=2, column=1, pady=5, padx=10)

    key_label = customtkinter.CTkLabel(master=frame, text="Key (letters):", font=("Roboto", 12))
    key_label.grid(row=4, column=0, pady=5, padx=10)
    key_entry = customtkinter.CTkEntry(master=frame)
    key_entry.grid(row=4, column=1, pady=5, padx=10)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 12))
    result_label.grid(row=3, column=0, pady=5, padx=10)
    result = customtkinter.CTkEntry(master=frame)
    result.grid(row=3, column=1, pady=5, padx=10)

    encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=lambda: result.insert(0, encrypt_transposition(message_entry.get(), key_entry.get())))
    encrypt_button.grid(row=5, column=0, pady=5, padx=10)

    decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=lambda: result.insert(0, decrypt_transposition(message_entry.get(), key_entry.get())))
    decrypt_button.grid(row=5, column=1, pady=5, padx=10)

    upload_button = customtkinter.CTkButton(master=frame, text="Upload File", command=lambda: upload_file(message_entry))
    upload_button.grid(row=6, column=0, columnspan=2, pady=5, padx=10)

    download_button = customtkinter.CTkButton(master=frame, text="Download File", command=lambda: download_file(result.get()))
    download_button.grid(row=7, column=0, columnspan=2, pady=5, padx=10)

    home_button = customtkinter.CTkButton(master=frame, text="Home", command=open_home_scene)
    home_button.grid(row=8, column=0, columnspan=2, pady=5, padx=10)

def encrypt_transposition(message, key):
    numeric_key = convert_key_to_numbers(key)
    if numeric_key is None:
        return "Error: Key must be letters only."

    col_length = max(numeric_key)
    result = ['' for _ in range(col_length)]

    for index, char in enumerate(message):
        column = numeric_key[index % len(numeric_key)] - 1
        result[column] += char

    return ''.join(result)

def decrypt_transposition(ciphertext, key):
    numeric_key = convert_key_to_numbers(key)
    if numeric_key is None:
        return "Error: Key must be letters only."

    col_length = len(numeric_key)
    # Calculate the number of full rows and the additional cells in the incomplete row
    full_rows, extra_cols = divmod(len(ciphertext), col_length)

    # Create lists to hold the plaintext data for each column based on numeric_key order
    plaintext_cols = [''] * col_length
    col_index = 0
    start_index = 0

    for i, slot in sorted(enumerate(numeric_key), key=lambda x: x[1]):
        # Determine the number of characters in the current column
        if i < extra_cols:
            char_count = full_rows + 1
        else:
            char_count = full_rows
        # Slice characters for the column out of the ciphertext
        plaintext_cols[i] = ciphertext[start_index:start_index + char_count]
        start_index += char_count

    # Convert the columns of text back into a single string row by row
    decrypted_message = []
    for row in range(full_rows + 1):  # +1 to handle the extra row containing less than col_length characters
        for j in range(col_length):
            if row < len(plaintext_cols[j]):
                decrypted_message.append(plaintext_cols[j][row])

    return ''.join(decrypted_message)

def upload_file(message_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

def open_substitution_scene(result=None):
    clear_frame()
    label1 = customtkinter.CTkLabel(master=frame, text="Substitution Cipher", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)
    message_label = customtkinter.CTkLabel(master=frame, text="Message:", font=("Roboto", 12))
    message_label.grid(row=2, column=0, pady=5, padx=10)
    message_entry = customtkinter.CTkEntry(master=frame)
    message_entry.grid(row=2, column=1, pady=5, padx=10)

    key_label = customtkinter.CTkLabel(master=frame, text="Key (letters):", font=("Roboto", 12))
    key_label.grid(row=4, column=0, pady=5, padx=10)
    key_entry = customtkinter.CTkEntry(master=frame)
    key_entry.grid(row=4, column=1, pady=5, padx=10)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 12))
    result_label.grid(row=3, column=0, pady=5, padx=10)
    result_entry = customtkinter.CTkEntry(master=frame)
    result_entry.grid(row=3, column=1, pady=5, padx=10)

    encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=lambda: result_entry.insert(0, encrypt_substitution(message_entry.get(), key_entry.get())))
    encrypt_button.grid(row=5, column=0, pady=5, padx=10)

    decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=lambda: result_entry.insert(0, decrypt_substitution(message_entry.get(), key_entry.get())))
    decrypt_button.grid(row=5, column=1, pady=5, padx=10)

    upload_button = customtkinter.CTkButton(master=frame, text="Upload File", command=lambda: upload_file_substitution(message_entry, result_entry))
    upload_button.grid(row=6, column=0, columnspan=2, pady=5, padx=10)
    download_button = customtkinter.CTkButton(master=frame, text="Download File",
                                              command=lambda: download_file(result_entry.get()))
    download_button.grid(row=7, column=0, columnspan=2, pady=5, padx=10)
    home_button = customtkinter.CTkButton(master=frame, text="Home", command=open_home_scene)
    home_button.grid(row=8, column=0, columnspan=2, pady=5, padx=10)

def encrypt_substitution(message, key):
    if not key.isalpha():
        return "Error: Key must be letters only."

    key = key.upper()
    if len(set(key)) != 26:
        return "Error: Key must be 26 distinct letters of the alphabet."

    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encryption_map = {alphabet[i]: key[i] for i in range(26)}

    result = ''
    for char in message:
        if char.isalpha():
            result += encryption_map[char.upper()] if char.isupper() else encryption_map[char.upper()].lower()
        else:
            result += char

    return result


def decrypt_substitution(message, key):
    if not key.isalpha():
        return "Error: Key must be letters only."

    key = key.upper()
    if len(set(key)) != 26:
        return "Error: Key must be 26 distinct letters of the alphabet."

    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decryption_map = {key[i]: alphabet[i] for i in range(26)}

    result = ''
    for char in message:
        if char.isalpha():
            result += decryption_map[char.upper()] if char.isupper() else decryption_map[char.upper()].lower()
        else:
            result += char

    return result





def upload_file_transposition(message_entry, result_entry, key_enytry=None):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            encrypted_or_decrypted = encrypt_transposition(content, key_enytry.get())  # Assuming the key is already entered
            result_entry.delete(0, customtkinter.END)
            result_entry.insert(0, encrypted_or_decrypted)
def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)



def open_rot13_scene():
    clear_frame()
    label1 = customtkinter.CTkLabel(master=frame, text="Rot13 Cipher", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)
    message_label = customtkinter.CTkLabel(master=frame, text="Message:", font=("Roboto", 12))
    message_label.grid(row=2, column=0, pady=5, padx=10)
    message_entry = customtkinter.CTkEntry(master=frame)
    message_entry.grid(row=2, column=1, pady=5, padx=10)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 12))
    result_label.grid(row=3, column=0, pady=5, padx=10)
    result = customtkinter.CTkEntry(master=frame)
    result.grid(row=3, column=1, pady=5, padx=10)

    encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=lambda: result.insert(0, encrypt_rot13(message_entry.get())))
    encrypt_button.grid(row=5, column=0, pady=5, padx=10)

    decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=lambda: result.insert(0, decrypt_rot13(message_entry.get())))
    decrypt_button.grid(row=5, column=1, pady=5, padx=10)

    upload_button = customtkinter.CTkButton(master=frame, text="Upload File for ROT13", command=lambda: upload_file_rot13(message_entry, result))
    upload_button.grid(row=6, column=0, columnspan=2, pady=5, padx=10)


    download_button = customtkinter.CTkButton(master=frame, text="Download File", command=lambda: download_file(result.get()))
    download_button.grid(row=7, column=0, columnspan=2, pady=5, padx=10)
    home_button = customtkinter.CTkButton(master=frame, text="Home", command=open_home_scene)
    home_button.grid(row=8, column=0, columnspan=2, pady=5, padx=10)
def encrypt_rot13(message):
    return ''.join([chr(((ord(char) - ord('a' if char.islower() else 'A') + 13) % 26) + ord('a' if char.islower() else 'A')) if char.isalpha() else char for char in message])

def decrypt_rot13(message):
    return encrypt_rot13(message)


def upload_file_rot13(message_entry, result_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)



def upload_file_substitution(message_entry, result_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            encrypted_or_decrypted = encrypt_substitution(content, key_entry.get()) # type: ignore
            result_entry.delete(0, customtkinter.END)
            result_entry.insert(0, encrypted_or_decrypted)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)


def open_affine_scene(result=None):
    clear_frame()
    label1 = customtkinter.CTkLabel(master=frame, text="Affine Cipher", font=("Roboto", 30))
    label1.grid(row=0, column=0, columnspan=2, pady=12, padx=10)
    message_label = customtkinter.CTkLabel(master=frame, text="Message:", font=("Roboto", 12))
    message_label.grid(row=2, column=0, pady=5, padx=10)
    message_entry = customtkinter.CTkEntry(master=frame)
    message_entry.grid(row=2, column=1, pady=5, padx=10)

    key_label_a = customtkinter.CTkLabel(master=frame, text="Key A (letter):", font=("Roboto", 12))
    key_label_a.grid(row=4, column=0, pady=5, padx=10)
    key_entry_a = customtkinter.CTkEntry(master=frame)
    key_entry_a.grid(row=4, column=1, pady=5, padx=10)

    key_label_b = customtkinter.CTkLabel(master=frame, text="Key B (letter):", font=("Roboto", 12))
    key_label_b.grid(row=5, column=0, pady=5, padx=10)
    key_entry_b = customtkinter.CTkEntry(master=frame)
    key_entry_b.grid(row=5, column=1, pady=5, padx=10)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 12))
    result_label.grid(row=3, column=0, pady=5, padx=10)
    result_entry = customtkinter.CTkEntry(master=frame)
    result_entry.grid(row=3, column=1, pady=5, padx=10)

    encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=lambda: result_entry.insert(0, encrypt_affine(message_entry.get(), key_entry_a.get(), key_entry_b.get())))
    encrypt_button.grid(row=6, column=0, pady=5, padx=10)

    decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=lambda: result_entry.insert(0, decrypt_affine(message_entry.get(), key_entry_a.get(), key_entry_b.get())))
    decrypt_button.grid(row=6, column=1, pady=5, padx=10)

    upload_button = customtkinter.CTkButton(master=frame, text="Upload File", command=lambda: upload_file_affine(message_entry, result_entry, key_entry_a, key_entry_b))
    upload_button.grid(row=7, column=0, columnspan=2, pady=5, padx=10)
    download_button = customtkinter.CTkButton(master=frame, text="Download File",
                                              command=lambda: download_file(result_entry.get()))
    download_button.grid(row=8, column=0, columnspan=2, pady=5, padx=10)
    home_button = customtkinter.CTkButton(master=frame, text="Home", command=open_home_scene)
    home_button.grid(row=9, column=0, columnspan=2, pady=5, padx=10)

def encrypt_affine(message, key_a, key_b):
    if not key_a.isalpha() or not key_b.isalpha():
        return "Error: Key A and Key B must be letters."

    key_a = key_a.upper()
    key_b = key_b.upper()

    if gcd(ord(key_a) - ord('A'), 26) != 1:
        return "Error: Key A must be coprime with 26 (i.e., gcd(a, 26) = 1)."

    key_a_num = ord(key_a) - ord('A')
    key_b_num = ord(key_b) - ord('A')

    result = ''
    for char in message:
        if char.isalpha():
            if char.islower():
                result += chr(((key_a_num * (ord(char) - ord('a')) + key_b_num) % 26) + ord('a'))
            else:
                result += chr(((key_a_num * (ord(char) - ord('A')) + key_b_num) % 26) + ord('A'))
        else:
            result += char
    return result

def decrypt_affine(ciphertext, key_a, key_b):
    if not key_a.isalpha() or not key_b.isalpha():
        return "Error: Key A and Key B must be letters."

    key_a = key_a.upper()
    key_b = key_b.upper()

    if gcd(ord(key_a) - ord('A'), 26) != 1:
        return "Error: Key A must be coprime with 26 (i.e., gcd(a, 26) = 1)."

    key_a_num = ord(key_a) - ord('A')
    key_b_num = ord(key_b) - ord('A')

    key_a_inv = mod_inverse(key_a_num, 26)
    if key_a_inv is None:
        return "Error: Key A has no modular inverse (i.e., a is not coprime with 26)."

    result = ''
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                result += chr(((key_a_inv * (ord(char) - ord('a') - key_b_num)) % 26) + ord('a'))
            else:
                result += chr(((key_a_inv * (ord(char) - ord('A') - key_b_num)) % 26) + ord('A'))
        else:
            result += char
    return result

def upload_file_affine(message_entry, result_entry, key_entry_a, key_entry_b):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            result_entry.delete(0, customtkinter.END)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

open_home_scene()
root.mainloop()
