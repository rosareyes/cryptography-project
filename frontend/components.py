""" Práctica 1 - Criptografía 
* Rosa Reyes

components.py:
** components del frontend para mostrar la intefaz del chat y los formularios de login/register
 """

from fasthtml.common import *

def create_form(user_type: str, is_register: bool):
    ''' formularios para el login/registro de los usuarios'''
    
    # parámetros para el formulario y placeholders de texto dependiendo si es login o registro y del usuario
    form_type = "Registro" if is_register else "Inicio de sesión"
    placeholder_user = f"{user_type}: Nuevo usuario" if is_register else f"{user_type}: Tu usuario"
    placeholder_pass = f"{user_type}: Nueva contraseña" if is_register else f"{user_type}: Tu contraseña"
    btn_text = f"{form_type} como {user_type}"
    btn_cls = "btn-primary" if user_type == "Usuario-1" else "btn-secondary"
    
    #la función retorna html para el formulario usando los parámetros anteriores y los recibidos por la función
    return H2(
        f"{form_type} - {user_type}",
        cls="text-2xl text-center mb-4 mt-4"
    ), Form(
        Input(id=f"data-username-{user_type}", type="text", name="username", placeholder=placeholder_user, cls="input w-full mb-2"),
        Input(id=f"data-password-{user_type}", type="password", name="password", placeholder=placeholder_pass, cls="input w-full mb-2"),
        Button(btn_text, type="submit", cls=f"btn {btn_cls} w-full mt-2"),
        Button("¿Ya tienes una cuenta? Inicia sesión" if is_register else "¿No tienes cuenta? Regístrate",
               type="button", 
               # hx-post y hx-target para hacer peticiones asíncronas y cambiar el contenido del contenedor del formulario
               hx_post=f"/show_{'login' if is_register else 'register'}_form?user={user_type}",
               hx_target=f"#{user_type.lower()}-container", 
               cls="btn btn-link w-full mt-2"),
        method="post",
        # acción y hx-post para enviar los datos del formulario al endpoint de login/register
        action=f"/{'register' if is_register else 'login'}?user={user_type}",
        hx_post=f"/{'register' if is_register else 'login'}?user={user_type}",
        hx_target=f"#{user_type.lower()}-container",
        cls="mt-4",
    )

# Uso de la función create_form para crear los formularios de login y registro para los usuarios User1 y User2
def register_form_user1():
    return create_form("Usuario-1", is_register=True)

def register_form_user2():
    return create_form("Usuario-2", is_register=True)

def login_form_user1():
    return create_form("Usuario-1", is_register=False)

def login_form_user2():
    return create_form("Usuario-2", is_register=False)


def create_chat_form(user_type: str):
    '''Función para crear el formulario de chat'''
    
    # parámetros para el formulario y placeholders de texto dependiendo del usuario
    btn_cls = "btn-primary" if user_type == "Usuario-1" else "btn-secondary"
    
    return Form(
        Input(id=f"data-{user_type.lower()}", type="text", name=f"data-{user_type.lower()}", placeholder=f"{user_type}: Escribe tu mensaje...", cls="input w-full"),
        Button(f"Enviar ({user_type})", cls=f"btn {btn_cls} w-full mt-2"),
        method="post",
        action="/chat",
        # hx-post y hx-target para hacer peticiones asíncronas y cambiar el contenido del contenedor del historial de chat
        hx_post=f"/chat?sender={user_type}",
        hx_target="#chat-history-container",
        hx_encoding="urlencoded",
        hx_swap="innerHTML",
        cls="mt-4",
    )
    

def ChatMessage(content, sender, encrypted=None):
    '''Función para crear los bocadillos de chat'''
    
    # parametros para los bocadillos de chat, dependiendo del usuario que envía el mensaje
    bubble_class = "chat-bubble-secondary" if sender == "Usuario-2" else "chat-bubble-primary"
    align_class = "chat-end" if sender == "Usuario-2" else "chat-start"
    
    # texto adicional para mensajes encriptados
    encrypted_content = f"{encrypted})" if encrypted else ""
    
    # la función retorna html para los bocadillos de chat usando los parámetros anteriores y los recibidos por la función
    return Div(
        Div(
            Div(f"{content}", cls=f"chat-bubble {bubble_class}"),
            cls=f"chat {align_class}",
        ),
         Div(Div(f"Encrypted: {encrypted_content}", cls="text-gray-500"), cls=f"mb-2 {align_class}",),
        cls="mb-2",
    )