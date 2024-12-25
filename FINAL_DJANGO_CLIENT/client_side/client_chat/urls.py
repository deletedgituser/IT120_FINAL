from django.urls import path
from .views import register, login, send_message, inbox, logout

urlpatterns = [
    path("register/", register, name="register"),
    path("login/", login, name="login"),
    path("send_message/", send_message, name="send_message"),
    path("inbox/", inbox, name="inbox"),
    path("logout/", logout, name="logout"),
]