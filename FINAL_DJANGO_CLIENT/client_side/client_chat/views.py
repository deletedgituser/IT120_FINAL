import requests
from django.shortcuts import render, redirect
import base64
from client_chat.middlewares.encryption_middleware import EncryptionMiddleware

# Server-side URL
SERVER_URL = "http://127.0.0.1:8000/api/"

# Register View
def register(request):
    enc_instance = EncryptionMiddleware(None)
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        enc_username = enc_instance.encrypt_text(username)
        enc_password = enc_instance.encrypt_text(password)
        response = requests.post(SERVER_URL + "register/", data={"username": enc_username, "password": enc_password})
        if response.status_code == 201:
            return redirect("login")
    return render(request, "register.html")

# Login View
def login(request):
    token = request.session.get("token")
    if token:
        return redirect(f"/send_message/?token={token}")
    enc_instance = EncryptionMiddleware(None)
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        enc_username = enc_instance.encrypt_text(username)
        enc_password = enc_instance.encrypt_text(password)
        response = requests.post(SERVER_URL + "login/", data={"username": enc_username, "password": enc_password})
        
        if response.status_code == 200:
            request.session["token"] = response.json()["token"]
            token = request.session.get('token')
            return redirect(f"/send_message/?token={token}")
    return render(request, "login.html")

# Send Message View
def send_message(request):
    token = request.session.get("token")
    if token:
        if request.method == "POST":
            recipient = request.POST["recipient"]
            message = request.POST["message"]
            print(recipient)
            enc_instance = EncryptionMiddleware(None)
            enc_message = enc_instance.encrypt_text(message)
            headers = {"Authorization": f"Token {token}"}
            response = requests.post(SERVER_URL + "send_message/", data={"recipient": recipient, "message": enc_message}, headers=headers)
            if response.status_code == 200:
                return redirect("inbox")
        return render(request, "send_message.html")
    else:
        return redirect("login")

# Inbox View
def inbox(request):
    token = request.session.get("token")
    enc_instance = EncryptionMiddleware(None)
    if token:    
        headers = {"Authorization": f"Token {token}"}
        response = requests.get(SERVER_URL + "inbox/", headers=headers)
        
        toDisplayReceived = []
        toDisplaySent = []

        if response.status_code == 200:
            # Handle received messages
            received_messages = response.json().get('received_messages', [])  # Default to an empty list if key is missing
            for message in received_messages:
                try:
                    # Decrypt the encrypted content
                    decoded_content = enc_instance.decrypt_text(message['encrypted_content'])
                    message['decrypted_content'] = decoded_content
                    toDisplayReceived.append(message)
                except (KeyError, ValueError, base64.binascii.Error):
                    # Handle missing keys or decryption errors gracefully
                    message['decrypted_content'] = "Invalid content"
                    toDisplayReceived.append(message)

            # Handle sent messages
            sent_messages = response.json().get('sent_messages', [])  # Default to an empty list if key is missing
            for message in sent_messages:
                try:
                    # Decrypt the encrypted content
                    decoded_content = enc_instance.decrypt_text(message['encrypted_content'])
                    message['decrypted_content'] = decoded_content
                    toDisplaySent.append(message)
                except (KeyError, ValueError, base64.binascii.Error):
                    # Handle missing keys or decryption errors gracefully
                    message['decrypted_content'] = "Invalid content"
                    toDisplaySent.append(message)

        return render(request, "inbox.html", {
            "received_messages": toDisplayReceived,
            "sent_messages": toDisplaySent
        })
    else:
        return redirect("login")


# Logout View
def logout(request):
    token = request.session.get("token")
    if token:
        headers = {"Authorization": f"Token {token}"}
        response = requests.post(SERVER_URL + "logout/", headers=headers)
        if response.status_code == 200:
            message = response.json().get('message');
            print(message)
            request.session.flush()  # Clear the session
    return redirect(f"/login/?message={message}")