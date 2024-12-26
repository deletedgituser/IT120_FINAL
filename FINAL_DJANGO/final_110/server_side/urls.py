from django.urls import path
from .views import RegisterView, LoginView, SendMessageView, InboxView, LogoutView, UsersView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('send_message/', SendMessageView.as_view(), name='send_message'),
    path('inbox/', InboxView.as_view(), name='inbox'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('users/', UsersView.as_view(), name='users'),
]
