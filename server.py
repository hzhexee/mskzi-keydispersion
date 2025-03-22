import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import pickle
import base64

# Симметричные ключи (предполагается, что сервер знает их заранее)
key_AS = os.urandom(32)  # ключ для общения с Алисой
key_BS = os.urandom(32)  # ключ для общения с Бобом

# Асимметричные ключи
private_key_server = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_server = private_key_server.public_key()

# Словарь для хранения ключей клиентов
client_keys = {
    'Alice': {'symmetric': key_AS, 'public_key': None},
    'Bob': {'symmetric': key_BS, 'public_key': None}
}

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

def handle_symmetric_request(data, client_address):
    sender, recipient, nonce = pickle.loads(data)
    print(f"Получен запрос от {sender} для установки соединения с {recipient}")
    
    # Генерация сессионного ключа
    session_key = os.urandom(32)
    
    # Подготовка сообщения для получателя
    recipient_msg = pickle.dumps((session_key, sender))
    encrypted_recipient_msg = encrypt_symmetric(client_keys[recipient]['symmetric'], recipient_msg)
    
    # Подготовка сообщения для отправителя
    sender_msg = pickle.dumps((nonce, recipient, session_key, encrypted_recipient_msg))
    encrypted_sender_msg = encrypt_symmetric(client_keys[sender]['symmetric'], sender_msg)
    
    return encrypted_sender_msg

def handle_asymmetric_registration(data):
    client_name, public_key_bytes = pickle.loads(data)
    client_keys[client_name]['public_key'] = pickle.loads(public_key_bytes)
    print(f"Зарегистрирован открытый ключ для {client_name}")
    return pickle.dumps(public_key_server)

def handle_client(client_socket, client_address):
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            protocol_type = data[:1]
            message_data = data[1:]
            
            if protocol_type == b"S":  # Симметричный протокол
                response = handle_symmetric_request(message_data, client_address)
                client_socket.send(b"S" + response)
            elif protocol_type == b"A":  # Асимметричная регистрация ключей
                response = handle_asymmetric_registration(message_data)
                client_socket.send(b"A" + response)
            elif protocol_type == b"K":  # Запрос публичного ключа
                client_name = message_data.decode()
                if client_name in client_keys and client_keys[client_name]['public_key']:
                    public_key_bytes = pickle.dumps(client_keys[client_name]['public_key'])
                    client_socket.send(b"K" + public_key_bytes)
                else:
                    client_socket.send(b"E" + b"Public key not found")
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5000))
    server.listen(5)
    
    print("Доверенный центр запущен и ожидает подключений...")
    print(f"Ключ Алисы: {base64.b64encode(key_AS).decode()}")
    print(f"Ключ Боба: {base64.b64encode(key_BS).decode()}")
    
    try:
        while True:
            client_socket, client_address = server.accept()
            print(f"Подключение от {client_address}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("Сервер остановлен")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()