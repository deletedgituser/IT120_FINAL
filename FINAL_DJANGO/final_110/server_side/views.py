from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from .models import Message
from .serializers import MessageSerializer
from server_side.middlewares.encryption_middleware import EncryptionMiddleware

class RegisterView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        enc_instance = EncryptionMiddleware(None)
        
        username = request.data.get('username')
        password = request.data.get('password')
        dec_username = enc_instance.decrypt_text(username)
        dec_password = enc_instance.decrypt_text(password)
        user = User.objects.create_user(username=dec_username, password=dec_password)
        return Response({'message': 'User registered successfully'}, status=201)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        enc_instance = EncryptionMiddleware(None)
        
        username = request.data.get('username')
        password = request.data.get('password')
        dec_username = enc_instance.decrypt_text(username)
        dec_password = enc_instance.decrypt_text(password)
        user = authenticate(request, username=dec_username, password=dec_password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        return Response({'error': 'Invalid credentials'}, status=400)

class SendMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        recipient_username = request.data.get('recipient')
        message = request.data.get('message')

        # Find recipient
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            return Response({'error': 'Recipient not found'}, status=404)

        # Save encrypted message (encryption handled by middleware)
        Message.objects.create(
            sender=request.user,
            recipient=recipient,
            encrypted_content=message  # Middleware already encrypted this
        )
        return Response({'message': 'Message sent successfully'})

class InboxView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        messages = Message.objects.filter(recipient=request.user)
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Logged out successfully'}, status=200)
        except Exception:
            return Response({'error': 'Failed to log out'}, status=400)
