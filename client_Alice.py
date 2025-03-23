import socket
import json
import random
import base64
import time
import os
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
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000
BOB_HOST = '127.0.0.1'
BOB_PORT = 5001

# Настройки для Алисы
ALICE_ID = "Alice"
BOB_ID = "Bob"
SALT = b'salt_for_key_derivation'
ALICE_PASSWORD = "alice_secret_password"

# Генерируем долговременный ключ Алисы для симметричного протокола
E_A = generate_key(ALICE_PASSWORD, SALT)

# Генерация пары ключей для асимметричного протокола
alice_private_key, alice_public_key = generate_rsa_keypair()
alice_public_key_pem = serialize_public_key(alice_public_key)

# Генерируем случайное число N_A для симметричного протокола
N_A = random.randint(10000, 99999)

def symmetric_protocol():
    """Реализация симметричного протокола Нидхема-Шредера"""
    print("\n=== Симметричный протокол Нидхема-Шредера ===")
    print(f"Долговременный ключ Алисы: {E_A}")
    print(f"Случайное число N_A: {N_A}")
    
    result = communicate_with_server()
    
    if result:
        session_key, encrypted_for_bob = result
        time.sleep(1)  # Даем время Бобу запуститься
        communicate_with_bob_symmetric(session_key, encrypted_for_bob)

def asymmetric_protocol():
    """Реализация асимметричного протокола Нидхема-Шредера"""
    print("\n=== Асимметричный протокол Нидхема-Шредера ===")
    print(f"Открытый ключ Алисы: {alice_public_key_pem}")
    
    # Генерируем часть ключа k_A
    k_a = os.urandom(16).hex()
    print(f"Часть ключа Алисы k_A: {k_a}")
    
    # Получаем открытый ключ Боба
    bob_public_key_pem = get_bob_public_key()
    if not bob_public_key_pem:
        print("Не удалось получить открытый ключ Боба.")
        return
    
    bob_public_key = deserialize_public_key(bob_public_key_pem)
    
    # Запускаем протокол
    communicate_with_bob_asymmetric(k_a, bob_public_key)

def get_bob_public_key():
    """Получает открытый ключ Боба"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((BOB_HOST, BOB_PORT))
        
        message = {
            "type": "get_public_key",
            "sender": ALICE_ID
        }
        
        s.sendall(json.dumps(message).encode())
        response = json.loads(s.recv(4096).decode())
        
        if "error" in response:
            print(f"Ошибка при получении ключа Боба: {response['error']}")
            return None
        
        return response.get("public_key")

def communicate_with_server():
    """Отправка запроса Тренту и получение ответа (шаги 1-2)"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        
        # Формируем сообщение M0 = A, B, N_A
        message = {
            "type": "M0",
            "sender": ALICE_ID,
            "recipient": BOB_ID,
            "nonce": N_A
        }
        
        print("Отправляем серверу M0:", message)
        s.sendall(json.dumps(message).encode())
        
        # Получаем ответ от сервера M1 = E_A(N_A, B, K, E_B(K, A))
        response = json.loads(s.recv(4096).decode())
        
        if "error" in response:
            print(f"Ошибка от сервера: {response['error']}")
            return None
        
        if response.get("type") == "M1":
            encrypted_data = base64.b64decode(response["data"])
            
            # Расшифровываем сообщение M1
            decrypted_data = decrypt(encrypted_data, E_A)
            
            # Проверяем наличие N_A для аутентификации сервера
            if decrypted_data.get("nonce") != N_A:
                print("Ошибка: Неверный nonce в ответе сервера!")
                return None
            
            print("Получено M1 от сервера. Расшифровано:", decrypted_data)
            print("Аутентификация сервера успешна (N_A совпадает)")
            
            # Извлекаем ключ K и сообщение для Боба
            session_key = decrypted_data.get("key").encode()
            encrypted_for_bob = decrypted_data.get("encrypted_for_recipient")
            
            return session_key, encrypted_for_bob

def communicate_with_bob_symmetric(session_key, encrypted_for_bob):
    """Обмен сообщениями с Бобом (шаги 3-5) для симметричного протокола"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((BOB_HOST, BOB_PORT))
        
        # Формируем сообщение M2 = E_B(K, A)
        message = {
            "type": "M2",
            "protocol": "symmetric",
            "data": encrypted_for_bob
        }
        
        print("Отправляем Бобу M2")
        s.sendall(json.dumps(message).encode())
        
        # Получаем ответ от Боба M3 = E_K(N_B)
        response = json.loads(s.recv(4096).decode())
        
        if "error" in response:
            print(f"Ошибка от Боба: {response['error']}")
            return
        
        if response.get("type") == "M3":
            encrypted_data = base64.b64decode(response["data"])
            
            # Расшифровываем сообщение M3
            try:
                decrypted_data = decrypt(encrypted_data, session_key)
                N_B = decrypted_data.get("nonce")
                print(f"Получено M3 от Боба с N_B = {N_B}")
                
                # Формируем сообщение M4 = E_K(N_B - 1)
                message = {
                    "type": "M4",
                    "data": base64.b64encode(encrypt({"nonce": N_B - 1}, session_key)).decode()
                }
                
                print(f"Отправляем Бобу M4 с N_B - 1 = {N_B - 1}")
                s.sendall(json.dumps(message).encode())
                
                # Получаем подтверждение от Боба
                final_response = json.loads(s.recv(1024).decode())
                print(f"Финальный ответ от Боба: {final_response}")
                
                if final_response.get("status") == "success":
                    print(f"Установлен общий секретный ключ с Бобом: {session_key}")
                
            except Exception as e:
                print(f"Ошибка при расшифровке сообщения от Боба: {e}")

def communicate_with_bob_asymmetric(k_a, bob_public_key):
    """Реализация асимметричного протокола с Бобом"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((BOB_HOST, BOB_PORT))
        
        # Шаг 1: Отправляем M0 = P_B(A, k_A)
        message = {
            "type": "M0_asym",
            "protocol": "asymmetric",
            "data": asymmetric_encrypt({
                "sender": ALICE_ID,
                "k_a": k_a
            }, bob_public_key).decode()
        }
        
        print("Отправляем Бобу M0 с k_A")
        s.sendall(json.dumps(message).encode())
        
        # Получаем ответ от Боба M1 = P_A(k_A, k_B)
        response = json.loads(s.recv(4096).decode())
        
        if "error" in response:
            print(f"Ошибка от Боба: {response['error']}")
            return
        
        if response.get("type") == "M1_asym":
            encrypted_data = response["data"]
            
            # Расшифровываем сообщение M1
            try:
                decrypted_data = asymmetric_decrypt(encrypted_data, alice_private_key)
                received_k_a = decrypted_data.get("k_a")
                k_b = decrypted_data.get("k_b")
                
                print(f"Получено M1 от Боба с k_A = {received_k_a}, k_B = {k_b}")
                
                # Проверяем, соответствует ли полученный k_A отправленному
                if received_k_a != k_a:
                    print("Ошибка: полученный k_A не соответствует отправленному!")
                    return
                
                print("Аутентификация Боба успешна (k_A совпадает)")
                
                # Шаг 3: Отправляем M2 = P_B(k_B)
                message = {
                    "type": "M2_asym",
                    "data": asymmetric_encrypt({
                        "k_b": k_b
                    }, bob_public_key).decode()
                }
                
                print(f"Отправляем Бобу M2 с k_B = {k_b}")
                s.sendall(json.dumps(message).encode())
                
                # Получаем подтверждение от Боба
                final_response = json.loads(s.recv(1024).decode())
                print(f"Финальный ответ от Боба: {final_response}")
                
                if final_response.get("status") == "success":
                    # Формируем общий ключ из k_A и k_B
                    shared_key = combine_key_parts(k_a, k_b)
                    print(f"Установлен общий секретный ключ с Бобом: {shared_key}")
                
            except Exception as e:
                print(f"Ошибка при обработке сообщения от Боба: {e}")

def kerberos_protocol():
    """Инициализация протокола Kerberos"""
    try:
        # Соединение с сервером (Трентом)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Отправка запроса серверу
        alice_id = "alice"
        bob_id = "bob"
        message = f"KERBEROS{alice_id},{bob_id}"
        sock.sendall(message.encode())
        
        # Получение ответа от сервера
        response = sock.recv(4096)
        sock.close()
        
        if response.startswith(b"ERROR"):
            print(f"[ALICE] Ошибка от сервера: {response.decode()}")
            return None, None
            
        # Расшифровка ответа от сервера
        alice_key = generate_key("alice_password", b"alice_salt")
        decrypted_response = decrypt(response.decode(), alice_key)
        response_data = json.loads(decrypted_response)
        
        # Извлечение информации из ответа
        timestamp = response_data["timestamp"]
        lifetime = response_data["lifetime"]
        bob_id = response_data["bob_id"]
        session_key = response_data["session_key"]
        ticket_for_bob = response_data["ticket_for_bob"]
        
        print(f"[ALICE] Получен Kerberos-ответ от сервера")
        print(f"[ALICE] Сгенерирован сеансовый ключ для общения с Бобом")
        
        # Общение с Бобом
        return communicate_with_bob_kerberos(session_key, ticket_for_bob, timestamp)
        
    except Exception as e:
        print(f"[ALICE] Ошибка при выполнении протокола Kerberos: {e}")
        return None, None

def communicate_with_bob_kerberos(session_key, ticket_for_bob, timestamp):
    """Общение с Бобом по протоколу Kerberos"""
    try:
        # Соединение с Бобом
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((BOB_HOST, BOB_PORT))
        
        # Формирование аутентификатора
        alice_id = "alice"
        authenticator = json.dumps({
            "alice_id": alice_id,
            "timestamp": timestamp
        })
        encrypted_authenticator = encrypt(authenticator, session_key)
        
        # Отправка сообщения Бобу (аутентификатор + билет)
        message = f"KERBEROS{encrypted_authenticator},{ticket_for_bob}"
        sock.sendall(message.encode())
        
        # Получение ответа от Боба
        response = sock.recv(4096)
        
        if response.startswith(b"ERROR"):
            print(f"[ALICE] Ошибка от Боба: {response.decode()}")
            sock.close()
            return None, None
            
        # Расшифровка ответа от Боба
        decrypted_response = decrypt(response.decode(), session_key)
        bob_timestamp = int(decrypted_response)
        expected_timestamp = int(timestamp) + 1
        
        if bob_timestamp != expected_timestamp:
            print(f"[ALICE] Ошибка: неверная метка времени от Боба")
            sock.close()
            return None, None
            
        print(f"[ALICE] Аутентификация с Бобом успешно завершена")
        
        # Обмен сообщениями с Бобом
        while True:
            message = input("[ALICE] Введите сообщение для Боба (или 'exit' для выхода): ")
            if message.lower() == 'exit':
                break
                
            encrypted_message = encrypt(message, session_key)
            sock.sendall(encrypted_message.encode())
            
            response = sock.recv(4096)
            decrypted_response = decrypt(response.decode(), session_key)
            print(f"[BOB -> ALICE] {decrypted_response}")
            
        sock.close()
        return session_key, None
        
    except Exception as e:
        print(f"[ALICE] Ошибка при общении с Бобом: {e}")
        return None, None

def main():
    print("=== Клиент Алиса ===")
    
    while True:
        print("\nВыберите протокол:")
        print("1. Симметричный протокол Нидхема-Шредера")
        print("2. Асимметричный протокол Нидхема-Шредера")
        print("3. Протокол Kerberos")
        print("0. Выход")
        
        choice = input("Ваш выбор: ")
        
        if choice == "1":
            symmetric_protocol()
        elif choice == "2":
            asymmetric_protocol()
        elif choice == "3":
            kerberos_protocol()
        elif choice == "0":
            break
        else:
            print("Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()