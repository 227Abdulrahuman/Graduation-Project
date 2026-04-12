from django.shortcuts import render
from backend.core.models import *

def home_view(request):
    targets =  Target.objects.all()

    context = {
        'targets': targets
    }

    return render(request, 'core/index.html', context)