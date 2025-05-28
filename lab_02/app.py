from flask import Flask, render_template, request
from cipher.caesar import CaesarCipher
from cipher.railfence import RailFenceCipher
from cipher.playfair import PlayfairCipher
from cipher.transposition import TranspositionCipher
from cipher.vigenere import VigenereCipher  


app = Flask(__name__)

# Home page route
@app.route('/')
def home():
    return render_template('index.html')

# Caesar Cipher routes
@app.route('/caesar')
def caesar():
    return render_template('caesar.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        caesar = request.form['inputPlainText']
        key = int(request.form['inputKeyPlain'])
        encrypted_text = CaesarCipher.encrypt_text(caesar, key)
        return render_template('caesar.html', result=f"Encrypted: {encrypted_text}")
    except (ValueError, KeyError):
        return render_template('caesar.html', result="Error: Invalid input or key")

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        caesar = request.form['inputCipherText']
        key = int(request.form['inputKeyCipher'])
        decrypted_text = CaesarCipher.decrypt_text(caesar, key)
        return render_template('caesar.html', result=f"Decrypted: {decrypted_text}")
    except (ValueError, KeyError):
        return render_template('caesar.html', result="Error: Invalid input or key")

# Vigenere Cipher routes
@app.route('/vigenere')
def vigenere():
    return render_template('vigenere.html')

@app.route('/encrypt', methods=['POST'])
def vigenere_encrypt():
    try:
        text = request.form['inputPlainText'].upper()
        key = request.form['inputKey'].upper()
        encrypted_text = VigenereCipher.vigenere_cipher_encrypt(text, key)
        return render_template('vigenere.html', result=f"Encrypted: {encrypted_text}")
    except (ValueError, KeyError):
        return render_template('vigenere.html', result="Error: Invalid input or key")

@app.route('/decrypt', methods=['POST'])
def vigenere_decrypt():
    try:
        text = request.form['inputCipherText'].upper()
        key = request.form['inputKeyCipher'].upper()
        decrypted_text = VigenereCipher.vigenere_cipher_decrypt(text, key)
        return render_template('vigenere.html', result=f"Decrypted: {decrypted_text}")
    except (ValueError, KeyError):
        return render_template('vigenere.html', result="Error: Invalid input or key")

def vigenere_cipher_encrypt(plain_text, key):
    encrypted_text = ""
    key = key * (len(plain_text) // len(key) + 1)
    key = key[:len(plain_text)]
    for p, k in zip(plain_text, key):
        if p.isalpha():
            shift = ord(k) - ord('A')
            encrypted_char = chr((ord(p) - ord('A') + shift) % 26 + ord('A'))
            encrypted_text += encrypted_char
        else:
            encrypted_text += p
    return encrypted_text

def vigenere_cipher_decrypt(cipher_text, key):
    decrypted_text = ""
    key = key * (len(cipher_text) // len(key) + 1)
    key = key[:len(cipher_text)]
    for c, k in zip(cipher_text, key):
        if c.isalpha():
            shift = ord(k) - ord('A')
            decrypted_char = chr((ord(c) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted_text += decrypted_char
        else:
            decrypted_text += c
    return decrypted_text

# RailFence Cipher routes
@app.route('/railfence')
def railfence():
    return render_template('railfence.html')

@app.route('/encrypt', methods=['POST'])
def railfence_encrypt():
    try:
        text = request.form['inputPlainText']
        key = int(request.form['inputKey'])
        if key < 2:
            return render_template('railfence.html', result="Error: Key must be at least 2")
        encrypted_text = RailFenceCipher.railfence_cipher_encrypt(text, key)
        return render_template('railfence.html', result=f"Encrypted: {encrypted_text}")
    except (ValueError, KeyError):
        return render_template('railfence.html', result="Error: Invalid input or key")

@app.route('/decrypt', methods=['POST'])
def railfence_decrypt():
    try:
        text = request.form['inputCipherText']
        key = int(request.form['inputKeyCipher'])
        if key < 2:
            return render_template('railfence.html', result="Error: Key must be at least 2")
        decrypted_text = RailFenceCipher.railfence_cipher_decrypt(text, key)
        return render_template('railfence.html', result=f"Decrypted: {decrypted_text}")
    except (ValueError, KeyError):
        return render_template('railfence.html', result="Error: Invalid input or key")

def railfence_cipher_encrypt(plain_text, key):
    rail = [''] * key
    row, step = 0, 1
    for char in plain_text:
        rail[row] += char
        if row == 0:
            step = 1
        elif row == key - 1:
            step = -1
        row += step
    return ''.join(rail)

def railfence_cipher_decrypt(cipher_text, key):
    rail = [['\n' for _ in range(len(cipher_text))] for _ in range(key)]
    row, col, step = 0, 0, 1
    for i in range(len(cipher_text)):
        rail[row][col] = '*'
        if row == 0:
            step = 1
        elif row == key - 1:
            step = -1
        row += step
        col += 1
    index = 0
    for i in range(key):
        for j in range(len(cipher_text)):
            if rail[i][j] == '*' and index < len(cipher_text):
                rail[i][j] = cipher_text[index]
                index += 1
    result = []
    row, col, step = 0, 0, 1
    for i in range(len(cipher_text)):
        result.append(rail[row][col])
        if row == 0:
            step = 1
        elif row == key - 1:
            step = -1
        row += step
        col += 1
    return ''.join(result)

# PlayFair Cipher routes
@app.route('/playfair')
def playfair():
    return render_template('playfair.html')

@app.route('/encrypt', methods=['POST'])
def playfair_encrypt():
    try:
        text = request.form['inputPlainText'].upper().replace('J', 'I')
        key = request.form['inputKey'].upper()
        encrypted_text = PlayfairCipher.playfair_cipher_encrypt(text, key)
        return render_template('playfair.html', result=f"Encrypted: {encrypted_text}")
    except (ValueError, KeyError):
        return render_template('playfair.html', result="Error: Invalid input or key")

@app.route('/decrypt', methods=['POST'])
def playfair_decrypt():
    try:
        text = request.form['inputCipherText'].upper()
        key = request.form['inputKeyCipher'].upper()
        decrypted_text = PlayfairCipher.playfair_cipher_decrypt(text, key)
        return render_template('playfair.html', result=f"Decrypted: {decrypted_text}")
    except (ValueError, KeyError):
        return render_template('playfair.html', result="Error: Invalid input or key")

def playfair_cipher_encrypt(plain_text, key):
    matrix = generate_playfair_matrix(key)
    plain_text = plain_text.replace(" ", "")
    if len(plain_text) % 2 != 0:
        plain_text += 'X'
    digraphs = [plain_text[i:i+2] for i in range(0, len(plain_text), 2)]
    encrypted_text = ""
    for a, b in digraphs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            encrypted_text += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            encrypted_text += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            encrypted_text += matrix[row1][col2] + matrix[row2][col1]
    return encrypted_text

def playfair_cipher_decrypt(cipher_text, key):
    matrix = generate_playfair_matrix(key)
    digraphs = [cipher_text[i:i+2] for i in range(0, len(cipher_text), 2)]
    decrypted_text = ""
    for a, b in digraphs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            decrypted_text += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            decrypted_text += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            decrypted_text += matrix[row1][col2] + matrix[row2][col1]
    return decrypted_text

def generate_playfair_matrix(key):
    key = key.replace("J", "I").replace(" ", "")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = ''.join(dict.fromkeys(key))
    matrix_string = key + ''.join(c for c in alphabet if c not in key)
    matrix = [[matrix_string[i * 5 + j] for j in range(5)] for i in range(5)]
    return matrix

def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None

# Transposition Cipher routes
@app.route('/transposition')
def transposition():
    return render_template('transposition.html')

@app.route('/encrypt', methods=['POST'])
def transposition_encrypt():
    try:
        text = request.form['inputPlainText']
        key = request.form['inputKey']
        encrypted_text = TranspositionCipher.transposition_cipher_encrypt(text, key)
        return render_template('transposition.html', result=f"Encrypted: {encrypted_text}")
    except (ValueError, KeyError):
        return render_template('transposition.html', result="Error: Invalid input or key")

@app.route('/decrypt', methods=['POST'])
def transposition_decrypt():
    try:
        text = request.form['inputCipherText']
        key = request.form['inputKeyCipher']
        decrypted_text = TranspositionCipher.transposition_cipher_decrypt(text, key)
        return render_template('transposition.html', result=f"Decrypted: {decrypted_text}")
    except (ValueError, KeyError):
        return render_template('transposition.html', result="Error: Invalid input or key")

def transposition_cipher_encrypt(plain_text, key):
    num_cols = len(key)
    num_rows = -(-len(plain_text) // num_cols)
    grid = [''] * num_cols
    for i, char in enumerate(plain_text):
        grid[i % num_cols] += char
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    encrypted_text = ''
    for col in key_order:
        encrypted_text += grid[col]
    return encrypted_text

def transposition_cipher_decrypt(cipher_text, key):
    num_cols = len(key)
    num_rows = -(-len(cipher_text) // num_cols)
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    col_lengths = [num_rows] * num_cols
    for i in range(len(cipher_text) % num_cols):
        col_lengths[key_order[i]] -= 1
    grid = [''] * num_cols
    pos = 0
    for i, col in enumerate(key_order):
        grid[col] = cipher_text[pos:pos + col_lengths[i]]
        pos += col_lengths[i]
    decrypted_text = ''
    for i in range(num_rows):
        for j in range(num_cols):
            if i < len(grid[j]):
                decrypted_text += grid[j][i]
    return decrypted_text

# RSA Cipher route (placeholder)
@app.route('/rsa')
def rsa():
    return "RSA Cipher page (to be implemented)"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)