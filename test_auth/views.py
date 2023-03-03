from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.core.serializers import serialize
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from test_auth.serializers import LoginSerializer, RegisterSerializer


@ensure_csrf_cookie
def get_csrf_token(request):
    return JsonResponse({'details': 'CSRF cookie set'})


@require_POST
def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')

    if username is None or password is None:
        return JsonResponse(
            {'error': 'Please enter both username and password'},
            status=400
        )

    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)
        return JsonResponse({'detail': 'success'})
    else:
        return JsonResponse({'error': 'Invalid Credentials'})


class LoginView:
    serializer = LoginSerializer


class RegisterAPIView(CreateAPIView):
    serializer_class = RegisterSerializer
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        print(user)

        return Response({'status': 'success', 'message': 'User created successfully'})


class TestAuth(APIView):
    authentication_classes = [SessionAuthentication, JWTAuthentication]

    def get(self, request):
        return Response({'detail': 'You are authenticated via any one of methods'})


class TestAuthJWT(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        return Response({'detail': 'You are authenticated via JWT', 'user': request.user.username})


class TestAuthCSRF(APIView):
    authentication_classes = [SessionAuthentication]

    def get(self, request):
        return Response({'detail': 'You are authenticated via CSRF', 'user': request.user.username})
