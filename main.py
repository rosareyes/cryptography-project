""" Práctica 1 - Criptografía 
* Rosa Reyes

main.py:
** main file para el frontend y los endpoints de la aplicación
 """
import os
from dotenv import load_dotenv
from dataclasses import dataclass
from backend.backend import  init_db, register_user, login_user 
from backend.crypto import decrypt_key_with_rsa, encrypt_key_with_certificate, verify_certificate, encrypt_message, decrypt_message, sign_message, verify_signature
from frontend.components import create_form, create_chat_form, ChatMessage, register_form_user1, register_form_user2
from fasthtml.common import FastHTML, Script, Link, H1,H2, Div, Request, serve
from colorama import init, Back,Style,Fore
import base64

# cargar variables de entorno
load_dotenv()

# resetear estilos de la terminal
init(autoreset=True)

# inicializar SQLite
init_db()

# data class para los endpoints de login/register
@dataclass
class User:
    username: str
    password: str

# frontend
app = FastHTML(
    hdrs=(
        Script(src="https://cdn.tailwindcss.com"), # css
        Link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/daisyui@4.11.1/dist/full.min.css")
    )
)

#  lista de mensajes del chat
chat_messages = []
decrypted_chat_messages = []

def decrypt_chat_message(msg):
    # Paso 1: descifrar la clave simétrica usando la clave privada del receptor
    encrypted_key = base64.b64decode(msg['encrypted_key'])
    private_key_path = f"certificates/{msg['recipient']}/private_key.pem"

    key_password = os.getenv(f"{msg['recipient']}_PRIVATE_KEY_PASSWORD").encode()
    symmetric_key = decrypt_key_with_rsa(encrypted_key, private_key_path,key_password)

    # Paso 2: descifrar el mensaje usando la clave simétrica
    decrypted_content = decrypt_message(msg['encrypted_message'], symmetric_key)

    # Paso 3: verificar la firma del mensaje con la clave pública del emisor
    signature = base64.b64decode(msg['signature'])
    sender_cert_path = f"certificates/{msg['sender']}/cert.pem"
    ca_cert_path = "certificates/AC1/cert.pem"

    sender_public_key = verify_certificate(sender_cert_path, ca_cert_path)
    is_valid = verify_signature(decrypted_content, signature, sender_public_key)

    # Paso 4: verificar si la firma es válida
    if is_valid:
        print(f"Verificación de la firma exitosa para el mensaje: {decrypted_content}")
    else:
        print(f"Verificación de la firma fallida para el mensaje: {decrypted_content}")
        
        return ChatMessage("[FIRMA INVALIDA]", msg['sender'], msg['encrypted_message'])

    # Paso 5: crear el componente de mensaje de chat
    chat_message = ChatMessage(decrypted_content, msg['sender'], msg['encrypted_message'])
    return chat_message

""" RUTAS DEL FRONTEND Y ENDPOINTS """

@app.route("/")
def home():
    
    return  H1("Práctica Criptografía - Envío seguro de mensajes", cls="text-2xl text-center mb-4 mt-4"),H2(
            "Cifrado híbrido, firma y certificados digitales", cls="text-blue-400 font-medium text-xl text-center mb-4 mt-4"),Div(
            Div(
                register_form_user1(),
                id="usuario-1-container",
                cls="w-1/4 p-4"
            ),
           Div(
            Div(
                id="chat-history-container",
                cls="w-full bg-white p-4 shadow-md rounded-lg overflow-y-auto max-h-[600px]"
            ),
            cls="flex justify-between w-1/2"),
            Div(
                register_form_user2(),
                id="usuario-2-container",
                cls="w-1/4 p-4"
            ),  
            cls="flex justify-between w-full",
            id="registration-container"
        )

# login form
@app.route("/show_login_form", methods=["POST"])
async def show_login_form(request: Request):
    user_type = request.query_params.get('user')
    return create_form(user_type, is_register=False)

    
# registration form
@app.route("/show_register_form", methods=["POST"])
async def show_register_form(request: Request):
    user_type = request.query_params.get('user')
    return create_form(user_type, is_register=True)


# registro de usuarios
@app.route("/register")
def post(user: User, request):
    userType = request.query_params.get("user")
    success, message = register_user(user.username, user.password)
    form = create_form(userType, is_register=False) if success else create_form(userType, is_register=True)
    return Div(f"{message} para {user.username}", cls="text-green-500 text-center") if success else Div(message, cls="text-red-500 text-center"), form


# login de usuarios
@app.route("/login")
def post(user: User, request):
    userType = request.query_params.get("user")
    success, message = login_user(user.username, user.password)
    form = create_chat_form(userType) if success else create_form(userType, is_register=False)
    return Div(f"{message}", cls="text-green-500 text-center") if success else Div(message, cls="text-red-500 text-center"), form

# chat msgs
@app.route("/chat", methods=["POST"])
async def add_message(request):
    form_data = await request.form()
    sender = request.query_params.get("sender", "Usuario-1")
    user_input = form_data.get("data-usuario-1") if sender == "Usuario-1" else form_data.get("data-usuario-2")
    if user_input:
        print(Back.GREEN + Fore.BLACK + "--------------------------------------------------------------------------------------------------------------------------------")
        print(Back.GREEN + Fore.BLACK + "--------------------------------------- EMPIEZA PROCESO CRIPTOGRÁFICO... -------------------------------------------------------")
        print(Back.GREEN + Fore.BLACK + "--------------------------------------------------------------------------------------------------------------------------------")
        print("\n" + Fore.MAGENTA + Style.BRIGHT + "--------------------------------------------------------- EMISOR ---------------------------------------------------------------")
        print("\n" + Fore.GREEN + "** " + Style.RESET_ALL + "Mensaje en claro:" + Fore.GREEN + f" {user_input}")
        # Paso 1: Generar una clave simétrica nueva para cada mensaje
        encryption_key = os.urandom(32)
        # Paso 2: Cifrar la clave simétrica con la clave pública del destinatario
        recipient = "Usuario-2" if sender == "Usuario-1" else "Usuario-1"

        encrypted_key = encrypt_key_with_certificate(encryption_key,
                                                    f"certificates/{recipient}/cert.pem",
                                                    "certificates/AC1/cert.pem" 
)

        # Paso 3: Cifrar el mensaje con la clave simétrica
        encrypted_message = encrypt_message(user_input, encryption_key)

        # Paso 4: Firmar el mensaje con la clave privada del emisor
        sender_private_key_path = f"certificates/{sender}/private_key.pem"
        key_password = os.getenv(f"{sender}_PRIVATE_KEY_PASSWORD").encode() 
        signature = sign_message(user_input, sender_private_key_path,key_password)
        signature_base64 = base64.b64encode(signature).decode("utf-8")

        # "envias" el mensaje cifrado
        chat_messages.append({
                              "encrypted_message": encrypted_message, 
                              "sender": sender,
                              "recipient": recipient,
                              # aquí enviamos la clave simétrica cifrada con la clave pública del destinatario
                              "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'), 
                               "signature": signature_base64}),
                                # no envíamos el certificado porque al descifrar el mensaje cogemos la ruta del certificado del emisor directamente
        
        # desciframos el mensaje y lo añadimos al chat en la UI
        new_message = chat_messages[-1]
        decrypted_message = decrypt_chat_message(new_message)
        decrypted_chat_messages.append(decrypted_message)

        return Div(
            Div(
                *decrypted_chat_messages,
                id="chat-history"
            )
        )
    else:
        return Div("No se recibió ningún mensaje", cls="text-red-500")

# iniciar la aplicación
serve()

