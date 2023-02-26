
import json
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse


@ensure_csrf_cookie
def set_csrf_token(request):
    return JsonResponse({'details': 'CSRF cookie set'})


@require_POST
def login_view(request):
    data = json.loads(request.body)
    
