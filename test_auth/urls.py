from django.urls import path

from test_auth.views import RegisterAPIView, TestAuth, login_view, set_csrf_token

urlpatterns = [
    path('set-csrf/', set_csrf_token, name='set-CSRF'),
    path('login/', login_view, name='login'),
    path('test-auth/', TestAuth.as_view(), name='test_auth'),
    path('register/', RegisterAPIView.as_view(), name='register')
]
