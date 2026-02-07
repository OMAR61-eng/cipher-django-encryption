from django.shortcuts import render
import random
import numpy as np
import string
import math
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ------------------------------------------------
# Caesar Cipher
# ------------------------------------------------
def caesar_encrypt(text, key):
    cipher = ""
    for char in text:
        if char == " ":
            cipher += " "
        elif char.isupper():
            cipher += chr((ord(char) + key - 65) % 26 + 65)
        elif char.islower():
            cipher += chr((ord(char) + key - 97) % 26 + 97)
        else:
            cipher += char
    return cipher

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)


# Monoalphabetic Cipher
def generate_mono_key():
    alphabet = list("abcdefghijklmnopqrstuvwxyz")
    shuffled = alphabet[:]
    random.shuffle(shuffled)
    return ''.join(shuffled)

def mono_encrypt(text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = ""
    for char in text:
        if char.islower() and char in alphabet:
            index = alphabet.index(char)
            result += key[index]
        elif char.isupper() and char.lower() in alphabet:
            index = alphabet.index(char.lower())
            result += key[index].upper()
        else:
            result += char  
    return result

def mono_decrypt(text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = ""
    for char in text:
        if char.islower() and char in key:
            index = key.index(char)
            result += alphabet[index]
        elif char.isupper() and char.lower() in key:
            index = key.index(char.lower())
            result += alphabet[index].upper()
        else:
            result += char  
    return result
# ------------------------------------------------
# Playfair Cipher
# ------------------------------------------------
def create_playfair_matrix(keyword):
    # Replace J with I
    keyword = keyword.upper().replace('J', 'I')
    # Create key with unique letters
    key = ""
    for char in keyword:
        if char not in key and char.isalpha():
            key += char
    
    # Add remaining alphabet
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # without J
    for char in alphabet:
        if char not in key:
            key += char
    
    # Create 5x5 matrix
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(list(key[i:i+5]))
    return matrix

def find_position(matrix, char):
    char = char.upper()
    if char == 'J':
        char = 'I'
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return (i, j)
    return None

def playfair_encrypt(text, keyword):
    # Clean text (remove non-alpha, replace J with I)
    text = ''.join(filter(str.isalpha, text.upper().replace('J', 'I')))
    
    # Create matrix
    matrix = create_playfair_matrix(keyword)
    
    # Create pairs
    pairs = []
    i = 0
    while i < len(text):
        if i+1 >= len(text):
            pairs.append(text[i] + 'X')
            i += 1
        elif text[i] == text[i+1]:
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i] + text[i+1])
            i += 2
    
    # Encrypt pairs
    result = ""
    for pair in pairs:
        a, b = pair[0], pair[1]
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        
        if row_a == row_b:  # Same row
            result += matrix[row_a][(col_a+1)%5] + matrix[row_b][(col_b+1)%5]
        elif col_a == col_b:  # Same column
            result += matrix[(row_a+1)%5][col_a] + matrix[(row_b+1)%5][col_b]
        else:  # Rectangle
            result += matrix[row_a][col_b] + matrix[row_b][col_a]
    
    return result

def playfair_decrypt(text, keyword):
    # Clean text
    text = ''.join(filter(str.isalpha, text.upper()))
    
    # Create matrix
    matrix = create_playfair_matrix(keyword)
    
    # Decrypt pairs
    result = ""
    for i in range(0, len(text), 2):
        if i+1 < len(text):
            a, b = text[i], text[i+1]
            row_a, col_a = find_position(matrix, a)
            row_b, col_b = find_position(matrix, b)
            
            if row_a == row_b:  # Same row
                result += matrix[row_a][(col_a-1)%5] + matrix[row_b][(col_b-1)%5]
            elif col_a == col_b:  # Same column
                result += matrix[(row_a-1)%5][col_a] + matrix[(row_b-1)%5][col_b]
            else:  # Rectangle
                result += matrix[row_a][col_b] + matrix[row_b][col_a]
    
    return result.lower()

# ------------------------------------------------
# Vigenère Cipher
# ------------------------------------------------
def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(k) - ord('a') for k in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            # A-Z: 65-90, a-z: 97-122
            base = ord('A') if char.isupper() else ord('a')
            # Convert letter to number (0-25), add key, convert back
            key_index = key_as_int[i % key_length]
            # Apply transformation
            result += chr((ord(char) - base + key_index) % 26 + base)
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(k) - ord('a') for k in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            # A-Z: 65-90, a-z: 97-122
            base = ord('A') if char.isupper() else ord('a')
            # Convert letter to number (0-25), subtract key, convert back
            key_index = key_as_int[i % key_length]
            # Apply transformation
            result += chr((ord(char) - base - key_index) % 26 + base)
        else:
            result += char
    return result

# ------------------------------------------------
# Hill Cipher
# ------------------------------------------------
def hill_encrypt(text, key):
    # Convert key to 2x2 matrix
    matrix = np.array(key).reshape(2, 2)
    
    # Prepare text (remove spaces, ensure even length)
    text = text.lower().replace(" ", "")
    if len(text) % 2 != 0:
        text += "x"
    
    result = ""
    # Process text in pairs
    for i in range(0, len(text), 2):
        # Convert pair to vector of numbers (0-25)
        pair = [ord(c) - ord('a') for c in text[i:i+2]]
        # Matrix multiplication and modulo 26
        encrypted_pair = np.dot(matrix, pair) % 26
        # Convert back to letters
        result += ''.join([chr(int(n) + ord('a')) for n in encrypted_pair])
    
    return result

def hill_decrypt(text, key):
    # Convert key to 2x2 matrix
    matrix = np.array(key).reshape(2, 2)
    
    # Calculate inverse matrix
    det = int(np.round(np.linalg.det(matrix))) % 26
    # Find modular multiplicative inverse
    for i in range(26):
        if (det * i) % 26 == 1:
            det_inv = i
            break
    else:
        raise ValueError("Matrix is not invertible in Z26")
    
    # Adjugate matrix
    adj = np.array([
        [matrix[1, 1], -matrix[0, 1]],
        [-matrix[1, 0], matrix[0, 0]]
    ]) % 26
    
    # Inverse matrix in Z26
    inv_matrix = (det_inv * adj) % 26
    
    result = ""
    # Process text in pairs
    for i in range(0, len(text), 2):
        # Convert pair to vector of numbers (0-25)
        pair = [ord(c) - ord('a') for c in text[i:i+2]]
        # Matrix multiplication and modulo 26
        decrypted_pair = np.dot(inv_matrix, pair) % 26
        # Convert back to letters
        result += ''.join([chr(int(n) + ord('a')) for n in decrypted_pair])
    
    return result

# ------------------------------------------------
# Rail Fence Cipher
# ------------------------------------------------
def rail_fence_encrypt(text, rails):
    if rails < 2:
        return text
    
    # Create empty fence
    fence = [[""] * len(text) for _ in range(rails)]
    
    # Fill fence
    rail, direction = 0, 1
    for i, char in enumerate(text):
        fence[rail][i] = char
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    # Read fence
    result = ""
    for rail in fence:
        result += "".join([char for char in rail if char])
    
    return result

def rail_fence_decrypt(text, rails):
    if rails < 2:
        return text
    
    # Create empty fence
    fence = [[None] * len(text) for _ in range(rails)]
    
    # Mark positions
    rail, direction = 0, 1
    for i in range(len(text)):
        fence[rail][i] = True
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    # Fill marked positions with text
    index = 0
    for i in range(rails):
        for j in range(len(text)):
            if fence[i][j] is True:
                fence[i][j] = text[index]
                index += 1
    
    # Read zigzag
    result = ""
    rail, direction = 0, 1
    for i in range(len(text)):
        result += fence[rail][i]
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    return result

# ------------------------------------------------
# One-Time Pad Cipher
# ------------------------------------------------
def generate_key(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def one_time_pad_encrypt(text, key):
    result = ""
    for i, char in enumerate(text):
        if char.isalpha():
            # Determine base (uppercase or lowercase)
            base = ord('A') if char.isupper() else ord('a')
            key_char = key[i % len(key)]
            key_base = ord('A') if key_char.isupper() else ord('a')
            # XOR operation in 0-25 range
            shift = (ord(char) - base) ^ (ord(key_char) - key_base)
            # Convert back to letter
            result += chr(shift + base)
        else:
            result += char
    return result

def one_time_pad_decrypt(text, key):
    # One-time pad decryption is the same as encryption
    return one_time_pad_encrypt(text, key)
# ------------------------------------------------
# Row Transposition Cipher
# ------------------------------------------------
def row_transposition_encrypt(text, key):
    # Calculate dimensions
    num_columns = len(key)
    num_rows = math.ceil(len(text) / num_columns)
    
    # Create grid and fill with text
    grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
    for i, char in enumerate(text):
        if i < len(text):
            row = i // num_columns
            col = i % num_columns
            grid[row][col] = char
    
    # Read columns according to key order
    result = ""
    key_order = [i[0] for i in sorted(enumerate(key), key=lambda x: x[1])]
    for col in key_order:
        for row in range(num_rows):
            if row < len(grid) and col < len(grid[row]) and grid[row][col]:
                result += grid[row][col]
    
    return result

def row_transposition_decrypt(text, key):
    # Calculate dimensions
    num_columns = len(key)
    num_rows = math.ceil(len(text) / num_columns)
    
    # Create empty grid
    grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
    
    # Calculate column lengths (might be uneven in last row)
    col_lengths = [num_rows for _ in range(num_columns)]
    short_cols = num_columns * num_rows - len(text)
    if short_cols > 0:
        key_order = [i[0] for i in sorted(enumerate(key), key=lambda x: x[1])]
        for i in range(short_cols):
            col_lengths[key_order[-(i+1)]] -= 1
    
    # Fill grid column by column according to key
    key_order = [i[0] for i in sorted(enumerate(key), key=lambda x: x[1])]
    index = 0
    for col_idx in key_order:
        for row in range(col_lengths[col_idx]):
            grid[row][col_idx] = text[index]
            index += 1
    
    # Read grid row by row
    result = ""
    for row in grid:
        result += ''.join(row)
    
    return result

# ------------------------------------------------
# Block Cipher (Simple XOR ECB Mode)
# ------------------------------------------------
def block_encrypt(text, key):
    block_size = 4
    
    # Pad text to multiple of block size
    padded_text = text.ljust(((len(text) + block_size - 1) // block_size) * block_size)
    
    # Divide into blocks
    blocks = [padded_text[i:i+block_size] for i in range(0, len(padded_text), block_size)]
    
    # Encrypt each block
    result = ""
    for j, block in enumerate(blocks):
        encrypted_block = ""
        for i, char in enumerate(block):
            # XOR with key character (key is repeated if needed)
            key_char = key[(j + i) % len(key)]
            encrypted_block += chr(ord(char) ^ ord(key_char))
        result += encrypted_block
    
    # Convert to hex for safe storage
    return result.encode('utf-8').hex()

def block_decrypt(cipher_hex, key):
    try:
        # Convert hex back to bytes and then to string
        cipher_bytes = bytes.fromhex(cipher_hex)
        cipher_text = cipher_bytes.decode('utf-8', errors='replace')
        
        # Divide into blocks
        block_size = 4
        blocks = [cipher_text[i:i+block_size] for i in range(0, len(cipher_text), block_size)]
        
        # Decrypt each block
        result = ""
        for j, block in enumerate(blocks):
            decrypted_block = ""
            for i, char in enumerate(block):
                # XOR with same key character
                key_char = key[(j + i) % len(key)]
                decrypted_block += chr(ord(char) ^ ord(key_char))
            result += decrypted_block
        
        # Remove padding
        return result.rstrip('\x00 ')
    except Exception as e:
        return f"Decryption failed: {e}"

# ------------------------------------------------
# Feistel Cipher (Simplified)
# ------------------------------------------------
def feistel_round(left, right, key):
    # Simple function: add key and take modulo 256
    def f_function(data, key):
        return (data + key) % 256
    
    # New left is the old right
    new_left = right
    # New right is old left XOR f(old right, key)
    new_right = left ^ f_function(right, key)
    
    return new_left, new_right

def feistel_encrypt(text):
    # Add padding if needed
    if len(text) % 2 != 0:
        text += 'x'
    
    result = ""
    # Process in pairs of characters
    for i in range(0, len(text), 2):
        # Convert to numbers (0-127)
        left = ord(text[i]) % 128
        right = ord(text[i+1]) % 128
        
        # Apply 4 rounds with different keys
        keys = [0x1, 0x2, 0x3, 0x4]
        for key in keys:
            left, right = feistel_round(left, right, key)
        
        # Convert to hex representation
        result += f"{left:02X}{right:02X}"
    
    return result

def feistel_decrypt(cipher_hex):
    if len(cipher_hex) % 4 != 0:
        raise ValueError("Invalid cipher length. Must be multiple of 4 hex chars.")
    
    result = ""
    # Process in blocks of 4 hex characters (2 bytes)
    for i in range(0, len(cipher_hex), 4):
        # Convert hex to numbers
        left = int(cipher_hex[i:i+2], 16)
        right = int(cipher_hex[i+2:i+4], 16)
        
        # Apply rounds in reverse with reversed keys
        keys = [0x4, 0x3, 0x2, 0x1]
        for key in keys:
            right, left = feistel_round(right, left, key)
        
        # Convert back to characters
        result += chr(left) + chr(right)
    
    # Remove padding if present
    return result.rstrip('x')

# ------------------------------------------------
# DES Encryption
# ------------------------------------------------
def des_encrypt(text):
    # Generate random 8-byte key
    key = get_random_bytes(8)
    
    # Create cipher object
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Pad text to multiple of 8 bytes
    padded_text = text.ljust((len(text) + 7) // 8 * 8)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_text.encode())
    
    # Return key and ciphertext as hex
    return {
        'key': key.hex(),
        'ciphertext': ciphertext.hex()
    }

def des_decrypt(ciphertext_hex, key_hex):
    try:
        # Convert hex to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        key = bytes.fromhex(key_hex)
        
        # Create cipher object
        decipher = DES.new(key, DES.MODE_ECB)
        
        # Decrypt and remove padding
        decrypted = decipher.decrypt(ciphertext).decode().rstrip('\x00 ')
        
        return decrypted
    except Exception as e:
        return f"Decryption failed: {e}"

# ------------------------------------------------
# AES Encryption
# ------------------------------------------------
def aes_encrypt(text):
    # Encode text to bytes
    data = text.encode()
    
    # Generate random 16-byte key
    key = get_random_bytes(16)
    
    # Create cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Encrypt with padding
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    # Return key and ciphertext as hex
    return {
        'key': key.hex(),
        'ciphertext': ciphertext.hex()
    }

def aes_decrypt(ciphertext_hex, key_hex):
    try:
        # Convert hex to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        key = bytes.fromhex(key_hex)
        
        # Create cipher object
        decipher = AES.new(key, AES.MODE_ECB)
        
        # Decrypt and remove padding
        plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)
        
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {e}"

# ------------------------------------------------
# Main View
# ------------------------------------------------
def encrypt(request):
    # Initialize context variables
    context = {
        'cipher': '',
        'message': '',
        'key': '',
        'used_key': '',
        'ciphertext': '',
        'decrypted': '',
    }
    
    # Process form submission
    if request.method == 'POST':
        cipher = request.POST.get('cipher', '')
        message = request.POST.get('message', '')
        key = request.POST.get('key', '')
        
        context['cipher'] = cipher
        context['message'] = message
        context['key'] = key
        
        # Skip processing if no message
        if not message:
            return render(request, 'cipher_app/index.html', context)
        
        try:
            # Process according to selected cipher
            if cipher == 'caesar':
                used_key = int(key) if key and key.isdigit() else 3
                ciphertext = caesar_encrypt(message, used_key)
                decrypted = caesar_decrypt(ciphertext, used_key)
                
            elif cipher == 'monoalphabetic':
                used_key = key if key else generate_mono_key()
                ciphertext = mono_encrypt(message, used_key)
                decrypted = mono_decrypt(ciphertext, used_key)
                
            elif cipher == 'playfair':
                used_key = key if key else 'monarchy'
                ciphertext = playfair_encrypt(message, used_key)
                decrypted = playfair_decrypt(ciphertext, used_key)
                
            elif cipher == 'vigenere':
                used_key = key if key else 'key'
                ciphertext = vigenere_encrypt(message, used_key)
                decrypted = vigenere_decrypt(ciphertext, used_key)
                
            elif cipher == 'hill':
                try:
                    used_key = [int(k) for k in key.split()] if key else [3, 3, 2, 5]
                    ciphertext = hill_encrypt(message, used_key)
                    decrypted = hill_decrypt(ciphertext, used_key)
                except Exception as e:
                    raise ValueError(f"Hill cipher error: {e}")
                
            elif cipher == 'rail_fence':
                used_key = int(key) if key and key.isdigit() else 3
                ciphertext = rail_fence_encrypt(message, used_key)
                decrypted = rail_fence_decrypt(ciphertext, used_key)
                
            elif cipher == 'one_time_pad':
                used_key = key if key and len(key) >= len(message) else generate_key(len(message))
                ciphertext = one_time_pad_encrypt(message, used_key)
                decrypted = one_time_pad_decrypt(ciphertext, used_key)
                
            elif cipher == 'row_transposition':
                if not key:
                    used_key = [1, 3, 0, 2]  # Default key
                else:
                    used_key = [int(k) for k in key.split()]
                ciphertext = row_transposition_encrypt(message, used_key)
                decrypted = row_transposition_decrypt(ciphertext, used_key)
                
            elif cipher == 'block':
                used_key = key if key else 'secret'
                ciphertext = block_encrypt(message, used_key)
                decrypted = block_decrypt(ciphertext, used_key)
                
            elif cipher == 'feistel':
                ciphertext = feistel_encrypt(message)
                decrypted = feistel_decrypt(ciphertext)
                used_key = "0x1, 0x2, 0x3, 0x4"  # Fixed keys
                
            elif cipher == 'des':
                result = des_encrypt(message)
                ciphertext = result['ciphertext']
                used_key = result['key']
                decrypted = des_decrypt(ciphertext, used_key)
                
            elif cipher == 'aes':
                result = aes_encrypt(message)
                ciphertext = result['ciphertext']
                used_key = result['key']
                decrypted = aes_decrypt(ciphertext, used_key)
                
            else:
                raise ValueError(f"Unknown cipher type: {cipher}")
            
            # Update context with results
            context['used_key'] = used_key
            context['ciphertext'] = ciphertext
            context['decrypted'] = decrypted
            
        except Exception as e:
            context['error'] = str(e)
    
    return render(request, 'cipher_app/index.html', context)