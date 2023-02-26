

from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView
from django.contrib.auth.models import User
from rest_framework import permissions

from test_auth.serializers import RegisterSerializer


@ensure_csrf_cookie
def set_csrf_token(request):
    return JsonResponse({'details': 'CSRF cookie set'})


@require_POST
def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    print('================')
    print(username, password)
    print("------------> ", request.POST)

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


class RegisterAPIView(CreateAPIView):
    serializer_class = RegisterSerializer
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        print(user)

        return Response({'status': 'success'})

        # token = RefreshToken.for_user(user)
        # token['username'] = user.username

        # headers = self.get_success_headers(serializer.data)
        # response = {
        #     'user_id': user.id,
        #     'username': user.username,
        #     'refresh': str(token),
        #     'access': str(token.access_token)
        # }
        # return Response(
        #     response, status=status.HTTP_201_CREATED, headers=headers
        # )

class TestAuth(APIView):
    authentication_classes = [SessionAuthentication]

    def get(self, request):
        print('request:user:--->', request.user)
        return Response({'detail': 'You are authenticated'})
