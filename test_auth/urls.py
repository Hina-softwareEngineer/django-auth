from django.urls import path

from test_auth.views import (RegisterAPIView, TestAuth, TestAuthCSRF,
                             TestAuthJWT, get_csrf_token, login_view)

urlpatterns = [
    path('get-csrf/', get_csrf_token, name='get_csrf_token'),
    path('login/', login_view, name='login'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('test-auth/', TestAuth.as_view(), name='test_auth'),
    path('test-jwt/', TestAuthJWT.as_view(), name='test_auth'),
    path('test-csrf/', TestAuthCSRF.as_view(), name='test_auth')
]
