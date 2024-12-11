""" Práctica 1 - Criptografía 
Entrega 2: Firma y Certificados Digitales
* Rosa Reyes

backend.py:
** backend para la autenticación de usuarios y almacenamiento de contraseñas en la base de datos
 """

import os
import sqlite3
import re
from typing import Tuple
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend

#creación de la base de datos
DB_NAME = 'users.db'

def init_db() -> None:
    """inicializar SQLite database"""

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor() #cursor para ejecutar comandos SQL
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            derived_key BLOB NOT NULL,
            salt BLOB NOT NULL
        )
    ''')
    conn.commit() #guardar cambios
    conn.close()

def verify_password(password: str) -> bool:
    """verificar fuerza contraseña"""

    regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{12,}$' #12 chars, una mayus, una minus, un digito
    return bool(re.match(regex, password))

def register_user(username: str, password: str) -> Tuple[bool, str]:
    """
    registra un nuevo usuario, derivando una clave segura de la contraseña y almacenándola en la base de datos.
    """

    if not verify_password(password):
        return False, "la contraseña debe tener al menos 12 chars, una mayúscula, una minúscula y un dígito"

    salt = os.urandom(16)
    # Derivar una clave segura a partir de la contraseña, utilizando Scrypt como KDF (función de derivación de clave)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    derived_key = kdf.derive(password.encode()) # clave derivada

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        # insertar usuario en la base de datos
        cursor.execute('INSERT INTO users (username, derived_key, salt) VALUES (?, ?, ?)', 
                       (username, derived_key, salt))
        conn.commit()
        conn.close()
        return True, "Usuario registrado con éxito"
    except sqlite3.IntegrityError:
        return False, "El nombre de usuario ya existe"

def login_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Inicio de sesión un usuario
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT derived_key, salt FROM users WHERE username = ?', (username,))
    # obtener la contraseña y el salt del usuario en una variable para posterior verificación
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        stored_hash, salt = user_data # extraer hash y salt
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        try:
            kdf.verify(password.encode(), stored_hash) # verificar la contraseña
            return True, "Inicio de sesión exitoso"
        except cryptography.exceptions.InvalidKey:
            return False, "La contraseña es incorrecta"
    else:
        return False, "El usuario no existe"
