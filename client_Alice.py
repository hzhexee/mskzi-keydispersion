import socket
import os
import time
import pickle
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# Предполагается, что ключ Алисы известен заранее (в реальности был бы безопасно передан)
key_AS = None  # Будет запрошен у пользователя

# Генерация асимметричных ключей
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

server_public_key = None

def encrypt_symmetric(key, message):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_symmetric(key, ciphertext):
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_asymmetric(public_key, message):
    return public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_asymmetric(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def register_public_key():
    global server_public_key
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))
    
    public_key_bytes = pickle.dumps(public_key)
    data = pickle.dumps(('Alice', public_key_bytes))
    client.send(b"A" + data)
    
    response = client.recv(4096)
    if response.startswith(b"A"):
        server_public_key = pickle.loads(response[1:])
        print("Публичный ключ зарегистрирован на сервере")
    
    client.close()

def get_bob_public_key():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))
    
    client.send(b"K" + b"Bob")
    
    response = client.recv(4096)
    if response.startswith(b"K"):
        bob_public_key = pickle.loads(response[1:])
        print("Получен публичный ключ Боба")
        return bob_public_key
    
    client.close()
    return None

def symmetric_protocol():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))
    
    # Генерация случайного числа
    nonce = os.urandom(16)
    
    # Отправка запроса серверу
    request = pickle.dumps(('Alice', 'Bob', nonce))
    client.send(b"S" + request)
    
    # Получение ответа от сервера
    response = client.recv(4096)
    if response.startswith(b"S"):
        encrypted_data = response[1:]
        decrypted_data = decrypt_symmetric(key_AS, encrypted_data)
        nonce_received, recipient, session_key, encrypted_bob_msg = pickle.loads(decrypted_data)
        
        # Проверка соответствия полученного nonce с отправленным
        if nonce == nonce_received:
            print("Nonce подтвержден, полученная информация корректна")
            print(f"Получен сессионный ключ для общения с {recipient}")
            
            # Подключение к Бобу для передачи части сообщения
            bob_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bob_client.connect(('localhost', 5001))  # Предполагается, что Боб слушает порт 5001
            
            # Отправка зашифрованного сообщения Бобу
            bob_client.send(encrypted_bob_msg)
            
            # Получение ответа от Боба
            encrypted_nonce_b = bob_client.recv(4096)
            decrypted_nonce_b = decrypt_symmetric(session_key, encrypted_nonce_b)
            nonce_b = pickle.loads(decrypted_nonce_b)
            
            # Отправка подтверждения Бобу
            confirmation = pickle.dumps(nonce_b - 1)
            bob_client.send(encrypt_symmetric(session_key, confirmation))
            
            print("Протокол успешно завершен, соединение с Бобом установлено")
            bob_client.close()
        else:
            print("Полученный nonce не соответствует отправленному")
    
    client.close()

def asymmetric_protocol():
    # Получаем публичный ключ Боба
    bob_public_key = get_bob_public_key()
    if not bob_public_key:
        print("Не удалось получить публичный ключ Боба")
        return
    
    # Создаем сокет для Боба
    bob_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_client.connect(('localhost', 5001))  # Предполагается, что Боб слушает порт 5001
    
    # Генерация случайного числа
    nonce_a = os.urandom(16)
    
    # Сообщение 1: A -> B: E_PK_B(N_A, A)
    message_1 = pickle.dumps((nonce_a, "Alice"))
    encrypted_message_1 = encrypt_asymmetric(bob_public_key, message_1)
    bob_client.send(encrypted_message_1)
    
    # Сообщение 2: B -> A: E_PK_A(N_A, N_B)
    encrypted_message_2 = bob_client.recv(4096)
    decrypted_message_2 = decrypt_asymmetric(private_key, encrypted_message_2)
    nonce_a_received, nonce_b = pickle.loads(decrypted_message_2)
    
    # Проверка nonce_a
    if nonce_a != nonce_a_received:
        print("Полученный nonce не соответствует отправленному")
        bob_client.close()
        return
    
    # Сообщение 3: A -> B: E_PK_B(N_B)
    message_3 = pickle.dumps(nonce_b)
    encrypted_message_3 = encrypt_asymmetric(bob_public_key, message_3)
    bob_client.send(encrypted_message_3)
    
    print("Асимметричный протокол успешно завершен, соединение с Бобом установлено")
    bob_client.close()

def main():
    global key_AS
    
    print("Клиент Алиса")
    key_input = input("Введите ключ для общения с сервером (base64): ")
    key_AS = base64.b64decode(key_input)
    
    while True:
        print("\nВыберите действие:")
        print("1. Зарегистрировать открытый ключ на сервере")
        print("2. Запустить симметричный протокол Нидхема-Шредера")
        print("3. Запустить асимметричный протокол Нидхема-Шредера")
        print("0. Выход")
        
        choice = input("Ваш выбор: ")
        
        if choice == "1":
            register_public_key()
        elif choice == "2":
            symmetric_protocol()
        elif choice == "3":
            asymmetric_protocol()
        elif choice == "0":
            break
        else:
            print("Неверный выбор")

if __name__ == "__main__":
    main()