
def create_matrix(key):
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    result = ""

    for char in key + alphabet:
        if char.isalpha() and char not in result:
            result += char

    return [list(result[i:i+5]) for i in range(0, 25, 5)]


def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = ''.join(c for c in text if c.isalpha())

    result = ""
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 >= len(text):
            b = 'X'
            i += 1
        elif text[i] == text[i+1]:
            b = 'X'
            i += 1
        else:
            b = text[i+1]
            i += 2

        result += a + b

    return result


def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j


def encrypt(text, key):
    matrix = create_matrix(key)
    text = prepare_text(text)

    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            result += matrix[r1][(c1+1) % 5]
            result += matrix[r2][(c2+1) % 5]

        elif c1 == c2:
            result += matrix[(r1+1) % 5][c1]
            result += matrix[(r2+1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def decrypt(text, key):
    matrix = create_matrix(key)
    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            result += matrix[r1][(c1-1) % 5]
            result += matrix[r2][(c2-1) % 5]

        elif c1 == c2:
            result += matrix[(r1-1) % 5][c1]
            result += matrix[(r2-1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result
