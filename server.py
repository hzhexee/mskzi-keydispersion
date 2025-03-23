import socket
import json
import random
import base64
import time
import secrets
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password, salt):
    """Генерирует ключ на основе пароля"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt(message, key):
    """Шифрует сообщение с помощью ключа"""
    f = Fernet(key)
    return f.encrypt(json.dumps(message).encode())

def decrypt(encrypted_message, key):
    """Расшифровывает сообщение с помощью ключа"""
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_message).decode())

def handle_kerberos_request(conn, data):
    """Обработка запроса по протоколу Kerberos"""
    try:
        # Получаем идентификаторы Алисы и Боба
        alice_id, bob_id = data.decode().split(',')
        
        # Генерируем метку времени
        timestamp = str(int(time.time()))
        lifetime = "3600"  # Время жизни билета в секундах (1 час)
        
        # Генерируем сеансовый ключ
        session_key = secrets.token_hex(16)
        
        # Получаем ключи для Алисы и Боба
        alice_key = generate_key("alice_password", b"alice_salt")
        bob_key = generate_key("bob_password", b"bob_salt")
        
        # Формируем билет для Боба
        ticket_for_bob = json.dumps({
            "timestamp": timestamp,
            "lifetime": lifetime,
            "alice_id": alice_id,
            "session_key": session_key
        })
        encrypted_ticket_for_bob = encrypt(ticket_for_bob, bob_key)
        
        # Формируем ответ для Алисы
        response_for_alice = json.dumps({
            "timestamp": timestamp,
            "lifetime": lifetime,
            "bob_id": bob_id,
            "session_key": session_key,
            "ticket_for_bob": encrypted_ticket_for_bob
        })
        encrypted_response_for_alice = encrypt(response_for_alice, alice_key)
        
        # Отправляем ответ Алисе
        conn.sendall(encrypted_response_for_alice.encode())
        print(f"[SERVER] Отправлен Kerberos-ответ для Алисы")
        return True
    except Exception as e:
        print(f"[SERVER] Ошибка при обработке Kerberos-запроса: {e}")
        conn.sendall(b"ERROR: " + str(e).encode())
        return False

def handle_symmetric_request(conn, data):
    """Обработка запроса по симметричному протоколу Нидхема-Шрёдера"""
    try:
        message = json.loads(data.decode())
        
        if message.get("type") == "M0":
            sender = message.get("sender")
            recipient = message.get("recipient")
            nonce = message.get("nonce")
            
            print(f"[SERVER] Получен запрос M0 от {sender} для {recipient} с nonce={nonce}")
            
            # Проверяем, есть ли у нас ключи для отправителя и получателя
            if sender not in keys or recipient not in keys:
                print(f"[SERVER] Ошибка: ключи для {sender} или {recipient} не найдены")
                conn.sendall(json.dumps({"error": "Неизвестный отправитель или получатель"}).encode())
                return False
            
            # Получаем ключи для отправителя и получателя
            sender_key = keys[sender]
            recipient_key = keys[recipient]
            
            # Генерируем сеансовый ключ
            session_key = Fernet.generate_key().decode()
            
            # Формируем сообщение для получателя (K, A)
            message_for_recipient = {
                "key": session_key,
                "sender": sender
            }
            encrypted_for_recipient = encrypt(message_for_recipient, recipient_key)
            
            # Формируем сообщение M1 для отправителя (N_A, B, K, E_B(K, A))
            message_for_sender = {
                "nonce": nonce,
                "recipient": recipient,
                "key": session_key,
                "encrypted_for_recipient": encrypted_for_recipient
            }
            encrypted_for_sender = encrypt(message_for_sender, sender_key)
            
            # Отправляем ответ
            response = {
                "type": "M1",
                "data": base64.b64encode(encrypted_for_sender).decode()
            }
            
            print(f"[SERVER] Отправлен ответ M1 для {sender}")
            conn.sendall(json.dumps(response).encode())
            return True
        else:
            print(f"[SERVER] Ошибка: неизвестный тип сообщения {message.get('type')}")
            conn.sendall(json.dumps({"error": "Неизвестный тип сообщения"}).encode())
            return False
    except Exception as e:
        print(f"[SERVER] Ошибка при обработке симметричного запроса: {e}")
        conn.sendall(json.dumps({"error": str(e)}).encode())
        return False

def handle_client(conn, addr):
    """Обработка соединения с клиентом"""
    print(f"[SERVER] Новое соединение: {addr}")
    
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
                
            command = data[:10].decode().strip()
            
            if command == "SYMMETRIC":
                handle_symmetric_request(conn, data[10:])
            elif command == "KERBEROSal":
                handle_kerberos_request(conn, data[10:])
            else:
                print(f"[SERVER] Неизвестная команда: {command}")
                conn.sendall(b"ERROR: Unknown command")
    except Exception as e:
        print(f"[SERVER] Ошибка при обработке клиента: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Соединение закрыто: {addr}")

# Параметры сервера
HOST = '127.0.0.1'
PORT = 5000

# Предварительно установленные секретные ключи для Алисы и Боба
# В реальной системе эти ключи должны быть защищены
SALT = b'salt_for_key_derivation'
ALICE_PASSWORD = "alice_secret_password"
BOB_PASSWORD = "bob_secret_password"

# Генерируем ключи для Алисы и Боба
E_A = generate_key(ALICE_PASSWORD, SALT)
E_B = generate_key(BOB_PASSWORD, SALT)

print(f"Ключ Алисы: {E_A}")
print(f"Ключ Боба: {E_B}")

# Словарь для хранения ключей участников
keys = {
    "Alice": E_A,
    "Bob": E_B
}

# Запускаем сервер
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Сервер запущен на {HOST}:{PORT}")
    
    while True:
        conn, addr = server_socket.accept()
        with conn:
            print(f"Подключение с {addr}")
            handle_client(conn, addr)