""" Práctica 1 - Criptografía 
* Rosa Reyes

 crypto.py:
** funciones para cifrar y descifrar mensajes y claves con AES-GCM y RSA
 """

import os
from colorama import Fore, Back, Style,init
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.oid import NameOID

# resetear estilos de la terminal
init(autoreset=True)

# AES-GCM Cifrado
def encrypt_message(message, key):
    aesgcm = AESGCM(key) # clase AESGCM para cifrar
    nonce = os.urandom(12)  # Nonce tiene que ser único (12 bytes para AES-GCM)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    encrypted_message = base64.b64encode(nonce + ciphertext).decode('utf-8')
    print("\n--------------------------------------------------------------------------------------------------------------------------------")
    print("\n" + Style.BRIGHT + Back.CYAN + Fore.BLACK +  "PASO 2:" + Style.RESET_ALL + " Cifrado del mensaje con la clave simétrica \n")
    print(Fore.GREEN + "** " + Style.RESET_ALL + f"Mensaje cifrado (AES-GCM): " + Fore.GREEN + f"{encrypted_message}")
    return encrypted_message

def decrypt_message(encrypted_message, key):
    """Descifrar un mensaje cifrado con AES-GCM"""
    try:
        encrypted_data = base64.b64decode(encrypted_message)
        nonce = encrypted_data[:12]  # primeros 12 bytes son el nonce
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        print("--------------------------------------------------------------------------------------------------------------------------------\n")
        print( Style.BRIGHT + Back.CYAN + Fore.BLACK + "PASO 4:" + Style.RESET_ALL + " Descifrado del mensaje con la clave simétrica\n")
        print(Fore.GREEN + "** " + Style.RESET_ALL + "Descifrando mensaje (AES-GCM):" + Fore.GREEN + f" {encrypted_message}")
        decrypted_message = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        print("\n" + Style.BRIGHT + Back.CYAN + Fore.BLACK +"** ... FINALMENTE SE DESCIFRA EL MENSAJE ... **")
        print("\n" + Fore.GREEN + "** " + Style.RESET_ALL + "Mensaje descifrado (AES-GCM):" + Fore.GREEN + f" {decrypted_message}")
        print(f"------------------------------------------------------------------------------------------------------------------------")
        return decrypted_message
    
    except Exception as e:
        print("Error descifrando el msg:", e)
        return ""


def decrypt_key_with_rsa(encrypted_key: bytes, private_key_pem_path: bytes, private_key_password: str) -> bytes:
    """ Descifrar la clave simétrica con la clave privada RSA del receptor  --> DESCIFRADO ASIMÉTRICO"""

    # Cargar la clave privada desde el archivo .pem
    with open(private_key_pem_path, 'rb') as pem_file:
        private_key = serialization.load_pem_private_key(pem_file.read(), password=private_key_password, backend=default_backend())

    # Descifrar la clave simétrica con la clave privada
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("\n--------------------------------------------------------------------------------------------------------------------------------")
    print(Fore.BLUE +  "\n** ...SE ENVÍA EL MENSAJE CIFRADO AL RECEPTOR... LO RECIBE, JUNTO A LA CLAVE SIMÉTRICA CIFRADA CON SU CLAVE PÚBLICA... **")
    print("\n--------------------------------------------------------------------------------------------------------------------------------")
    print("\n" + Fore.MAGENTA + Style.BRIGHT + "--------------------------------------------------------- RECEPTOR ---------------------------------------------------------------")
    print("\n" + Style.BRIGHT + Back.CYAN + Fore.BLACK + "PASO 3:" + Style.RESET_ALL + " Descifrado de la clave simétrica con la clave privada del receptor\n")
    print(Fore.GREEN + "** " + Style.RESET_ALL + "Longitud de la clave cifrada usada:" + Fore.GREEN + f" {len(encrypted_key) * 8} bits\n")
    print(Fore.GREEN + "** " + Style.RESET_ALL + "Clave simétrica descifrada (RSA):" + Fore.GREEN + f"\n{symmetric_key}\n")

    return symmetric_key


# ---------- Firma digital del mensaje ----------

def sign_message(message: str, private_key_path: str, private_key_password: str) -> bytes:
    """
    Firmar un mensaje usando la clave privada del emisor.
    :param message: El mensaje en claro.
    :param private_key_path: Ruta al archivo de clave privada del emisor.
    :return: La firma digital del mensaje.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=private_key_password, 
        )

    message_bytes = message.encode("utf-8")
    signature = private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature


def verify_signature(message: str, signature: bytes, public_key: bytes) -> bool:
    """
    Verificar la firma digital de un mensaje.
    :param message: El mensaje en claro.
    :param signature: La firma digital del mensaje.
    :param public_key_path: Ruta al archivo de clave pública del emisor.
    :return: True si la firma es válida, False en caso contrario.
    """
    message_bytes = message.encode("utf-8")
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        print( Style.BRIGHT + Back.CYAN + Fore.BLACK + "PASO 5:" + Style.RESET_ALL + " Verificación de la firma del mensaje\n")
        print(Fore.GREEN + "** " + Style.RESET_ALL + "Verificando la firma del mensaje:" + Fore.GREEN + f" {signature}\n")
        print(Fore.GREEN + "** " + Style.RESET_ALL + "Firma verificada con éxito" + Fore.GREEN + "** ")
        print(f"------------------------------------------------------------------------------------------------------------------------")
        return True
    except Exception as e:
        print(f"La verificación de la clave ha fallado: {e}")
        return False

def verify_certificate(cert_path: str, ca_cert_path: str) -> rsa.RSAPublicKey:
    """
    Verificar un certificado X.509 contra la CA.
    :param cert_path: ruta al archivo de certificado.
    :param ca_cert_path: ruta al archivo de certificado de la CA.
    :return: La clave pública del certificado.
    """
    with open(cert_path, "rb") as cert_file:
        cert = load_pem_x509_certificate(cert_file.read())

    with open(ca_cert_path, "rb") as ca_cert_file:
        ca_cert = load_pem_x509_certificate(ca_cert_file.read())

    print(Style.BRIGHT + Back.CYAN + Fore.BLACK + "Detalles del certificado:")
    print(Fore.GREEN + f"Sujeto: {cert.subject}")
    print(Fore.GREEN + f"Emisor: {cert.issuer}")
    print(Fore.GREEN + f"Longitud de la clave: {cert.public_key().key_size}")
    
    # Verificar la firma del certificado
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            SHA256()
        )
        print(Style.BRIGHT + Back.CYAN + Fore.BLACK + "Certificado verificado con éxito")
        print(Fore.GREEN + "** Sujeto: " + str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
        print(Fore.GREEN + "** Emisor del Certificado: " + str(cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
        print(Fore.GREEN + "** Algoritmo de clave pública: RSA")
        print(Fore.GREEN + "** Longitud de la clave: " + str(cert.public_key().key_size) + " bits")
    except Exception as e:
        print(Fore.RED + "Verificación del certificado fallida: " + str(e))
        raise

    return cert.public_key()

def encrypt_key_with_certificate(symmetric_key: bytes, cert_path: str, ca_cert_path: str) -> bytes:
    """  Cifrar la clave simétrica con la clave pública del destinatario (certificado) """
    public_key = verify_certificate(cert_path, ca_cert_path)
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key