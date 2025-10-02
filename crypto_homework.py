import string
import math
from collections import Counter

# Текст для шифрування
TEXT = """The artist is the creator of beautiful things. To reveal art and conceal the artist is art's aim. The critic is he who can translate into another manner or a new material his impression of beautiful things. The highest, as the lowest, form of criticism is a mode of autobiography. Those who find ugly meanings in beautiful things are corrupt without being charming. This is a fault. Those who find beautiful meanings in beautiful things are the cultivated. For these there is hope. They are the elect to whom beautiful things mean only Beauty. There is no such thing as a moral or an immoral book. Books are well written, or badly written. That is all. The nineteenth-century dislike of realism is the rage of Caliban seeing his own face in a glass. The nineteenth-century dislike of Romanticism is the rage of Caliban not seeing his own face in a glass. The moral life of man forms part of the subject matter of the artist, but the morality of art consists in the perfect use of an imperfect medium. No artist desires to prove anything. Even things that are true can be proved. No artist has ethical sympathies. An ethical sympathy in an artist is an unpardonable mannerism of style. No artist is ever morbid. The artist can express everything. Thought and language are to the artist instruments of an art. Vice and virtue are to the artist materials for an art. From the point of view of form, the type of all the arts is the art of the musician. From the point of view of feeling, the actor's craft is the type. All art is at once surface and symbol. Those who go beneath the surface do so at their peril. Those who read the symbol do so at their peril. It is the spectator, and not life, that art really mirrors. Diversity of opinion about a work of art shows that the work is new, complex, vital. When critics disagree the artist is in accord with himself. We can forgive a man for making a useful thing as long as he does not admire it. The only excuse for making a useless thing is that one admires it intensely. All art is quite useless."""

# ==================== ШИФР ВІЖЕНЕРА ====================

def vigenere_encrypt(text, key):
    """Шифрування тексту шифром Віженера"""
    result = []
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

def vigenere_decrypt(text, key):
    """Дешифрування тексту шифром Віженера"""
    result = []
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

def kasiski_examination(ciphertext):
    """Метод Касіскі для визначення довжини ключа"""
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    sequences = {}
    
    for seq_len in range(3, 6):
        for i in range(len(ciphertext) - seq_len):
            seq = ciphertext[i:i+seq_len]
            if seq in sequences:
                sequences[seq].append(i)
            else:
                sequences[seq] = [i]
    
    distances = []
    for seq, positions in sequences.items():
        if len(positions) > 1:
            for i in range(len(positions)-1):
                distances.append(positions[i+1] - positions[i])
    
    if distances:
        from math import gcd
        from functools import reduce
        key_length = reduce(gcd, distances)
        return key_length
    return 0

def friedman_test(ciphertext):
    """Тест Фрідмана для визначення довжини ключа"""
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    n = len(ciphertext)
    freq = Counter(ciphertext)
    
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    
    key_length = (0.027 * n) / ((n - 1) * ic - 0.038 * n + 0.065)
    return round(key_length)

# ==================== ШИФР ПЕРЕСТАНОВКИ ====================

def columnar_transposition_encrypt(text, key):
    """Простий шифр перестановки (колонковий)"""
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    
    text = ''.join(c for c in text if c.isalpha() or c.isspace())
    
    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)
    
    padded_text = text + 'X' * (num_rows * num_cols - len(text))
    
    matrix = [padded_text[i:i+num_cols] for i in range(0, len(padded_text), num_cols)]
    
    cipher = ''
    for col in key_order:
        for row in matrix:
            cipher += row[col]
    
    return cipher

def columnar_transposition_decrypt(cipher, key):
    """Дешифрування простого шифру перестановки"""
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    
    num_cols = len(key)
    num_rows = math.ceil(len(cipher) / num_cols)
    
    # Визначаємо кількість символів у кожній колонці
    num_full_cols = len(cipher) % num_cols
    if num_full_cols == 0:
        num_full_cols = num_cols
    
    matrix = [[''] * num_cols for _ in range(num_rows)]
    
    idx = 0
    for col_idx, col in enumerate(key_order):
        # Визначаємо кількість рядків для цієї колонки
        col_height = num_rows if col_idx < num_full_cols or num_full_cols == num_cols else num_rows - 1
        for row in range(col_height):
            if idx < len(cipher):
                matrix[row][col] = cipher[idx]
                idx += 1
    
    plaintext = ''.join(''.join(row) for row in matrix)
    return plaintext.rstrip('X')

def double_transposition_encrypt(text, key1, key2):
    """Подвійна перестановка"""
    first_pass = columnar_transposition_encrypt(text, key1)
    second_pass = columnar_transposition_encrypt(first_pass, key2)
    return second_pass

def double_transposition_decrypt(cipher, key1, key2):
    """Дешифрування подвійної перестановки"""
    first_pass = columnar_transposition_decrypt(cipher, key2)
    second_pass = columnar_transposition_decrypt(first_pass, key1)
    return second_pass

# ==================== ТАБЛИЧНИЙ ШИФР ====================

def create_playfair_matrix(key):
    """Створення матриці для шифру Плейфера"""
    key = ''.join(dict.fromkeys(key.upper().replace('J', 'I')))
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    matrix_string = key + ''.join(c for c in alphabet if c not in key)
    
    matrix = [list(matrix_string[i:i+5]) for i in range(0, 25, 5)]
    return matrix

def playfair_encrypt(text, key):
    """Шифрування шифром Плейфера (табличний шифр)"""
    matrix = create_playfair_matrix(key)
    
    text = text.upper().replace('J', 'I')
    text = ''.join(c for c in text if c.isalpha())
    
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    
    def find_position(char):
        for i, row in enumerate(matrix):
            if char in row:
                return i, row.index(char)
        return None
    
    cipher = []
    for a, b in pairs:
        row_a, col_a = find_position(a)
        row_b, col_b = find_position(b)
        
        if row_a == row_b:
            cipher.append(matrix[row_a][(col_a + 1) % 5])
            cipher.append(matrix[row_b][(col_b + 1) % 5])
        elif col_a == col_b:
            cipher.append(matrix[(row_a + 1) % 5][col_a])
            cipher.append(matrix[(row_b + 1) % 5][col_b])
        else:
            cipher.append(matrix[row_a][col_b])
            cipher.append(matrix[row_b][col_a])
    
    return ''.join(cipher)

def playfair_decrypt(cipher, key):
    """Дешифрування шифром Плейфера"""
    matrix = create_playfair_matrix(key)
    
    def find_position(char):
        for i, row in enumerate(matrix):
            if char in row:
                return i, row.index(char)
        return None
    
    pairs = [(cipher[i], cipher[i+1]) for i in range(0, len(cipher), 2)]
    
    plaintext = []
    for a, b in pairs:
        row_a, col_a = find_position(a)
        row_b, col_b = find_position(b)
        
        if row_a == row_b:
            plaintext.append(matrix[row_a][(col_a - 1) % 5])
            plaintext.append(matrix[row_b][(col_b - 1) % 5])
        elif col_a == col_b:
            plaintext.append(matrix[(row_a - 1) % 5][col_a])
            plaintext.append(matrix[(row_b - 1) % 5][col_b])
        else:
            plaintext.append(matrix[row_a][col_b])
            plaintext.append(matrix[row_b][col_a])
    
    return ''.join(plaintext)

# ==================== ДЕМОНСТРАЦІЯ ====================

if __name__ == "__main__":
    print("="*70)
    print("КРИПТОГРАФІЧНЕ ДОМАШНЄ ЗАВДАННЯ")
    print("="*70)
    
    # ШИФР ВІЖЕНЕРА - Рівень 1
    print("\n1. ШИФР ВІЖЕНЕРА (Рівень 1)")
    print("-" * 70)
    key_vigenere = "CRYPTOGRAPHY"
    encrypted_vigenere = vigenere_encrypt(TEXT, key_vigenere)
    decrypted_vigenere = vigenere_decrypt(encrypted_vigenere, key_vigenere)
    
    print(f"Ключ: {key_vigenere}")
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(encrypted_vigenere[:200])
    print(f"\nРозшифрований текст (перші 200 символів):")
    print(decrypted_vigenere[:200])
    print(f"\nПеревірка: {TEXT[:100] == decrypted_vigenere[:100]}")
    
    # ШИФР ВІЖЕНЕРА - Рівень 2
    print("\n\n2. ШИФР ВІЖЕНЕРА (Рівень 2) - Криптоаналіз")
    print("-" * 70)
    key_len_kasiski = kasiski_examination(encrypted_vigenere)
    key_len_friedman = friedman_test(encrypted_vigenere)
    print(f"Метод Касіскі: довжина ключа ≈ {key_len_kasiski}")
    print(f"Тест Фрідмана: довжина ключа ≈ {key_len_friedman}")
    print(f"Фактична довжина ключа: {len(key_vigenere)}")
    
    # ШИФР ПЕРЕСТАНОВКИ - Рівень 1
    print("\n\n3. ШИФР ПЕРЕСТАНОВКИ (Рівень 1)")
    print("-" * 70)
    key_transposition = "SECRET"
    encrypted_trans = columnar_transposition_encrypt(TEXT, key_transposition)
    decrypted_trans = columnar_transposition_decrypt(encrypted_trans, key_transposition)
    
    print(f"Ключ: {key_transposition}")
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(encrypted_trans[:200])
    print(f"\nРозшифрований текст (перші 200 символів):")
    print(decrypted_trans[:200])
    
    # ШИФР ПЕРЕСТАНОВКИ - Рівень 2
    print("\n\n4. ШИФР ПОДВІЙНОЇ ПЕРЕСТАНОВКИ (Рівень 2)")
    print("-" * 70)
    key1 = "SECRET"
    key2 = "CRYPTO"
    encrypted_double = double_transposition_encrypt(TEXT, key1, key2)
    decrypted_double = double_transposition_decrypt(encrypted_double, key1, key2)
    
    print(f"Ключ 1: {key1}")
    print(f"Ключ 2: {key2}")
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(encrypted_double[:200])
    print(f"\nРозшифрований текст (перші 200 символів):")
    print(decrypted_double[:200])
    
    # ТАБЛИЧНИЙ ШИФР - Рівень 1
    print("\n\n5. ТАБЛИЧНИЙ ШИФР ПЛЕЙФЕРА (Рівень 1)")
    print("-" * 70)
    key_playfair = "MATRIX"
    encrypted_playfair = playfair_encrypt(TEXT, key_playfair)
    decrypted_playfair = playfair_decrypt(encrypted_playfair, key_playfair)
    
    print(f"Ключ: {key_playfair}")
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(encrypted_playfair[:200])
    print(f"\nРозшифрований текст (перші 200 символів):")
    print(decrypted_playfair[:200])
    
    # ТАБЛИЧНИЙ ШИФР - Рівень 2 (комбінований)
    print("\n\n6. КОМБІНОВАНИЙ ШИФР (Рівень 2)")
    print("-" * 70)
    print("Віженер + Табличний шифр (Плейфер)")
    key_vig_combo = "CRYPTO"
    key_play_combo = "CRYPTO"
    
    # Спочатку Віженер
    encrypted_step1 = vigenere_encrypt(TEXT, key_vig_combo)
    print(f"\nКрок 1 - Шифр Віженера:")
    print(f"Ключ: {key_vig_combo}")
    print(f"Результат (перші 150 символів):")
    print(encrypted_step1[:150])
    
    # Потім Плейфер
    encrypted_combo = playfair_encrypt(encrypted_step1, key_play_combo)
    print(f"\nКрок 2 - Табличний шифр Плейфера:")
    print(f"Ключ: {key_play_combo}")
    print(f"Фінальний зашифрований текст (перші 150 символів):")
    print(encrypted_combo[:150])
    
    # Дешифрування (у зворотному порядку)
    print(f"\nДешифрування:")
    decrypted_step1 = playfair_decrypt(encrypted_combo, key_play_combo)
    print(f"Після Плейфера (перші 150 символів):")
    print(decrypted_step1[:150])
    
    decrypted_combo = vigenere_decrypt(decrypted_step1, key_vig_combo)
    print(f"Після Віженера (перші 150 символів):")
    print(decrypted_combo[:150])
    
    print(f"\n⚠️ Примітка: Шифр Плейфера видаляє пунктуацію та замінює J на I")
    print(f"Це нормальна поведінка для цього типу шифру.")
    
    print("\n" + "="*70)
    print("ЗАВДАННЯ ВИКОНАНО!")
    print("="*70)
