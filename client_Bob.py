import socket
import threading
import os
import pickle
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# Предполагается, что ключ Боба известен заранее (в реальности был бы безопасно передан)
key_BS = None  # Будет запрошен у пользователя

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
    data = pickle.dumps(('Bob', public_key_bytes))
    client.send(b"A" + data)
    
    response = client.recv(4096)
    if response.startswith(b"A"):
        server_public_key = pickle.loads(response[1:])
        print("Публичный ключ зарегистрирован на сервере")
    
    client.close()

def get_alice_public_key():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5000))
    
    client.send(b"K" + b"Alice")
    
    response = client.recv(4096)
    if response.startswith(b"K"):
        alice_public_key = pickle.loads(response[1:])
        print("Получен публичный ключ Алисы")
        return alice_public_key
    
    client.close()
    return None

def handle_symmetric_client(client_socket):
    # Получение зашифрованного сообщения от Алисы
    encrypted_data = client_socket.recv(4096)
    
    # Расшифровка сообщения
    decrypted_data = decrypt_symmetric(key_BS, encrypted_data)
    session_key, sender = pickle.loads(decrypted_data)
    
    print(f"Получен сессионный ключ для общения с {sender}")
    
    # Генерация случайного числа nonce_b
    nonce_b = 12345  # В реальном случае было бы случайное число
    
    # Отправка зашифрованного nonce_b Алисе
    encrypted_nonce_b = encrypt_symmetric(session_key, pickle.dumps(nonce_b))
    client_socket.send(encrypted_nonce_b)
    
    # Получение подтверждения от Алисы
    encrypted_confirmation = client_socket.recv(4096)
    decrypted_confirmation = decrypt_symmetric(session_key, encrypted_confirmation)
    confirmation = pickle.loads(decrypted_confirmation)
    
    if confirmation == nonce_b - 1:
        print("Подтверждение получено, соединение установлено")
    else:
        print("Ошибка подтверждения")
    
    client_socket.close()

def handle_asymmetric_client(client_socket):
    # Получение зашифрованного сообщения 1 от Алисы
    encrypted_message_1 = client_socket.recv(4096)
    
    # Расшифровка сообщения 1
    decrypted_message_1 = decrypt_asymmetric(private_key, encrypted_message_1)
    nonce_a, sender = pickle.loads(decrypted_message_1)
    
    print(f"Получено сообщение от {sender}")
    
    # Получение публичного ключа Алисы
    alice_public_key = get_alice_public_key()
    if not alice_public_key:
        print("Не удалось получить публичный ключ Алисы")
        client_socket.close()
        return
    
    # Генерация случайного числа nonce_b
    nonce_b = os.urandom(16)
    
    # Создание и отправка сообщения 2: B -> A: E_PK_A(N_A, N_B)
    message_2 = pickle.dumps((nonce_a, nonce_b))
    encrypted_message_2 = encrypt_asymmetric(alice_public_key, message_2)
    client_socket.send(encrypted_message_2)
    
    # Получение сообщения 3: A -> B: E_PK_B(N_B)
    encrypted_message_3 = client_socket.recv(4096)
    decrypted_message_3 = decrypt_asymmetric(private_key, encrypted_message_3)
    nonce_b_received = pickle.loads(decrypted_message_3)
    
    # Проверка nonce_b
    if nonce_b == nonce_b_received:
        print("Nonce подтвержден, соединение установлено")
    else:
        print("Полученный nonce не соответствует отправленному")
    
    client_socket.close()

def start_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5001))
    server.listen(5)
    
    print("Боб ожидает подключений на порту 5001...")
    
    try:
        while True:
            client_socket, client_address = server.accept()
            print(f"Подключение от {client_address}")
            
            # Определяем тип протокола по размеру сообщения
            # (асимметричное сообщение обычно больше)
            data = client_socket.recv(1, socket.MSG_PEEK)
            if len(data) > 0:
                # Возвращаем данные обратно в буфер
                client_socket.setblocking(False)
                try:
                    peek_data = client_socket.recv(256, socket.MSG_PEEK)
                    client_socket.setblocking(True)
                    
                    if len(peek_data) > 200:  # Предположим, что асимметричное сообщение > 200 байт
                        threading.Thread(target=handle_asymmetric_client, args=(client_socket,)).start()
                    else:
                        threading.Thread(target=handle_symmetric_client, args=(client_socket,)).start()
                except:
                    client_socket.setblocking(True)
                    threading.Thread(target=handle_symmetric_client, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("Сервер остановлен")
    finally:
        server.close()

def main():
    global key_BS
    
    print("Клиент Боб")
    key_input = input("Введите ключ для общения с сервером (base64): ")
    key_BS = base64.b64decode(key_input)
    
    # Запускаем поток для прослушивания подключений
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True
    listener_thread.start()
    
    while True:
        print("\nВыберите действие:")
        print("1. Зарегистрировать открытый ключ на сервере")
        print("0. Выход")
        
        choice = input("Ваш выбор: ")
        
        if choice == "1":
            register_public_key()
        elif choice == "0":
            break
        else:
            print("Неверный выбор")

if __name__ == "__main__":
    main()