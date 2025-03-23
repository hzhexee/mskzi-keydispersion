import socket
import json
import random
import base64
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

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

def generate_rsa_keypair():
    """Генерирует пару RSA ключей"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Сериализует открытый ключ RSA в формат PEM"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(pem).decode()

def deserialize_public_key(pem_base64):
    """Десериализует открытый ключ RSA из формата PEM"""
    pem = base64.b64decode(pem_base64)
    return serialization.load_pem_public_key(pem, backend=default_backend())

def asymmetric_encrypt(message, public_key):
    """Шифрует сообщение с помощью открытого ключа RSA"""
    message_bytes = json.dumps(message).encode()
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext)

def asymmetric_decrypt(encrypted_message, private_key):
    """Расшифровывает сообщение с помощью закрытого ключа RSA"""
    ciphertext = base64.b64decode(encrypted_message)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return json.loads(plaintext.decode())

def combine_key_parts(k_a, k_b):
    """Создает общий ключ из частей"""
    combined = f"{k_a}{k_b}".encode()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(combined)
    key_bytes = digest.finalize()
    return base64.urlsafe_b64encode(key_bytes)

# Параметры
BOB_HOST = '127.0.0.1'
BOB_PORT = 5001

# Настройки для Боба
BOB_ID = "Bob"
SALT = b'salt_for_key_derivation'
BOB_PASSWORD = "bob_secret_password"

# Генерируем долговременный ключ Боба для симметричного протокола
E_B = generate_key(BOB_PASSWORD, SALT)

# Генерация пары ключей для асимметричного протокола
bob_private_key, bob_public_key = generate_rsa_keypair()
bob_public_key_pem = serialize_public_key(bob_public_key)

# Генерируем случайное число N_B для симметричного протокола
N_B = random.randint(10000, 99999)

# Глобальные переменные для хранения ключей сессии
session_key = None
alice_id = None
alice_public_key_pem = None

def handle_symmetric_protocol(conn):
    """Обрабатывает симметричный протокол Нидхема-Шредера"""
    global session_key, alice_id
    
    # Получаем сообщение M2 = E_B(K, A)
    data = conn.recv(4096)
    message = json.loads(data.decode())
    
    if message.get("type") == "M2":
        encrypted_data = base64.b64decode(message["data"])
        
        # Расшифровываем сообщение M2
        try:
            decrypted_data = decrypt(encrypted_data, E_B)
            session_key = decrypted_data.get("key").encode()
            alice_id = decrypted_data.get("sender")
            
            print(f"Получено M2 от Алисы. Расшифровано: {decrypted_data}")
            print(f"Сеансовый ключ K: {session_key}")
            print(f"Отправитель: {alice_id}")
            
            # Формируем сообщение M3 = E_K(N_B)
            message = {
                "type": "M3",
                "data": base64.b64encode(encrypt({"nonce": N_B}, session_key)).decode()
            }
            
            print(f"Отправляем Алисе M3 с N_B = {N_B}")
            conn.sendall(json.dumps(message).encode())
            
            # Получаем сообщение M4 = E_K(N_B - 1)
            response = json.loads(conn.recv(4096).decode())
            
            if response.get("type") == "M4":
                encrypted_data = base64.b64decode(response["data"])
                
                # Расшифровываем сообщение M4
                try:
                    decrypted_data = decrypt(encrypted_data, session_key)
                    received_nonce = decrypted_data.get("nonce")
                    
                    print(f"Получено M4 от Алисы с nonce = {received_nonce}")
                    
                    # Проверяем, является ли полученное значение N_B - 1
                    if received_nonce == N_B - 1:
                        print("Аутентификация Алисы успешна (получен правильный N_B - 1)")
                        conn.sendall(json.dumps({"status": "success", "message": "Аутентификация успешна"}).encode())
                        print(f"Установлен общий секретный ключ с Алисой: {session_key}")
                    else:
                        print("Ошибка аутентификации Алисы (неверное значение N_B - 1)")
                        conn.sendall(json.dumps({"status": "error", "message": "Ошибка аутентификации"}).encode())
                    
                except Exception as e:
                    print(f"Ошибка при расшифровке M4: {e}")
                    conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode())
        
        except Exception as e:
            print(f"Ошибка при расшифровке M2: {e}")
            conn.sendall(json.dumps({"error": str(e)}).encode())
    else:
        conn.sendall(json.dumps({"error": "Неизвестный тип сообщения"}).encode())

def handle_public_key_request(conn):
    """Обрабатывает запрос на получение открытого ключа"""
    response = {
        "public_key": bob_public_key_pem
    }
    conn.sendall(json.dumps(response).encode())
    print("Отправлен открытый ключ Боба")

def handle_asymmetric_protocol(conn, message):
    """Обрабатывает асимметричный протокол Нидхема-Шредера"""
    if message.get("type") == "M0_asym":
        encrypted_data = message["data"]
        
        # Расшифровываем сообщение M0
        try:
            decrypted_data = asymmetric_decrypt(encrypted_data, bob_private_key)
            sender = decrypted_data.get("sender")
            k_a = decrypted_data.get("k_a")
            
            print(f"Получено M0 от Алисы с идентификатором {sender} и k_A = {k_a}")
            
            # Генерируем свою часть ключа k_B
            k_b = os.urandom(16).hex()
            print(f"Сгенерирована часть ключа k_B = {k_b}")
            
            # Запрашиваем открытый ключ Алисы, если еще не имеем
            if alice_public_key_pem is None:
                get_alice_public_key()
            
            if alice_public_key_pem is None:
                conn.sendall(json.dumps({"error": "Не удалось получить открытый ключ Алисы"}).encode())
                return
            
            alice_public_key = deserialize_public_key(alice_public_key_pem)
            
            # Формируем сообщение M1 = P_A(k_A, k_B)
            message = {
                "type": "M1_asym",
                "data": asymmetric_encrypt({
                    "k_a": k_a,
                    "k_b": k_b
                }, alice_public_key).decode()
            }
            
            print(f"Отправляем Алисе M1 с k_A = {k_a}, k_B = {k_b}")
            conn.sendall(json.dumps(message).encode())
            
            # Получаем сообщение M2 = P_B(k_B)
            response = json.loads(conn.recv(4096).decode())
            
            if response.get("type") == "M2_asym":
                encrypted_data = response["data"]
                
                # Расшифровываем сообщение M2
                try:
                    decrypted_data = asymmetric_decrypt(encrypted_data, bob_private_key)
                    received_k_b = decrypted_data.get("k_b")
                    
                    print(f"Получено M2 от Алисы с k_B = {received_k_b}")
                    
                    # Проверяем, соответствует ли полученный k_B отправленному
                    if received_k_b == k_b:
                        print("Аутентификация Алисы успешна (k_B совпадает)")
                        
                        # Формируем общий ключ из k_A и k_B
                        shared_key = combine_key_parts(k_a, k_b)
                        print(f"Установлен общий секретный ключ с Алисой: {shared_key}")
                        
                        conn.sendall(json.dumps({"status": "success", "message": "Аутентификация и обмен ключами успешны"}).encode())
                    else:
                        print("Ошибка аутентификации Алисы (неверное значение k_B)")
                        conn.sendall(json.dumps({"status": "error", "message": "Ошибка аутентификации"}).encode())
                    
                except Exception as e:
                    print(f"Ошибка при расшифровке M2: {e}")
                    conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode())
            
        except Exception as e:
            print(f"Ошибка при расшифровке M0: {e}")
            conn.sendall(json.dumps({"error": str(e)}).encode())
    else:
        conn.sendall(json.dumps({"error": "Неизвестный тип сообщения для асимметричного протокола"}).encode())

def get_alice_public_key():
    """Получает открытый ключ Алисы"""
    global alice_public_key_pem
    
    # В реальном сценарии здесь был бы запрос к серверу сертификатов
    # Для упрощения имитируем получение ключа от Алисы
    print("Имитация получения открытого ключа Алисы...")
    
    # Предположим, что ключ уже известен или получен из надежного источника
    alice_public_key_pem = input("Введите открытый ключ Алисы (из терминала Алисы): ")
    return alice_public_key_pem

def handle_kerberos_protocol(conn, message):
    """Обработка Kerberos-запроса от Алисы"""
    try:
        # Получаем данные от Алисы
        encrypted_authenticator, ticket_for_bob = message.decode().split(',')
        
        # Расшифровываем билет
        bob_key = generate_key("bob_password", b"bob_salt")
        decrypted_ticket = decrypt(ticket_for_bob, bob_key)
        ticket_data = json.loads(decrypted_ticket)
        
        # Извлекаем ключ сессии и другие данные из билета
        session_key = ticket_data["session_key"]
        timestamp = ticket_data["timestamp"]
        lifetime = ticket_data["lifetime"]
        alice_id = ticket_data["alice_id"]
        
        # Проверка срока действия билета
        current_time = int(time.time())
        if current_time > int(timestamp) + int(lifetime):
            print(f"[BOB] Ошибка: срок действия билета истек")
            conn.sendall(b"ERROR: Ticket expired")
            return False
            
        # Расшифровываем аутентификатор
        decrypted_authenticator = decrypt(encrypted_authenticator, session_key)
        authenticator_data = json.loads(decrypted_authenticator)
        
        # Проверка аутентификатора
        if authenticator_data["alice_id"] != alice_id:
            print(f"[BOB] Ошибка: идентификатор Алисы не совпадает")
            conn.sendall(b"ERROR: Invalid authenticator")
            return False
            
        if authenticator_data["timestamp"] != timestamp:
            print(f"[BOB] Ошибка: метка времени не совпадает")
            conn.sendall(b"ERROR: Invalid timestamp")
            return False
            
        # Формируем ответ для Алисы (timestamp + 1)
        modified_timestamp = str(int(timestamp) + 1)
        encrypted_response = encrypt(modified_timestamp, session_key)
        conn.sendall(encrypted_response.encode())
        
        print(f"[BOB] Аутентификация с Алисой успешно завершена")
        
        # Обмен сообщениями с Алисой
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                    
                decrypted_message = decrypt(data.decode(), session_key)
                print(f"[ALICE -> BOB] {decrypted_message}")
                
                response = input("[BOB] Введите ответ для Алисы: ")
                encrypted_response = encrypt(response, session_key)
                conn.sendall(encrypted_response.encode())
                
            except Exception as e:
                print(f"[BOB] Ошибка при обмене сообщениями: {e}")
                break
                
        return True
        
    except Exception as e:
        print(f"[BOB] Ошибка при обработке Kerberos-запроса: {e}")
        conn.sendall(b"ERROR: " + str(e).encode())
        return False

def start_server():
    """Запускает сервер для получения сообщений"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((BOB_HOST, BOB_PORT))
        server_socket.listen()
        print(f"Боб ожидает соединения на {BOB_HOST}:{BOB_PORT}")
        
        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Соединение с {addr}")
                
                data = conn.recv(4096)
                message = json.loads(data.decode())
                
                if message.get("type") == "get_public_key":
                    handle_public_key_request(conn)
                elif message.get("protocol") == "asymmetric":
                    handle_asymmetric_protocol(conn, message)
                elif message.get("protocol") == "kerberos":
                    handle_kerberos_protocol(conn, message)
                else:
                    handle_symmetric_protocol(conn)

# Основной блок
def main():
    print("=== Клиент Боб ===")
    print(f"Долговременный ключ Боба (симметричный): {E_B}")
    print(f"Открытый ключ Боба (асимметричный): {bob_public_key_pem[:50]}...")
    print(f"Случайное число N_B: {N_B}")
    
    # Запускаем сервер для обработки запросов
    start_server()

if __name__ == "__main__":
    main()