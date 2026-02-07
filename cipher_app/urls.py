from django.urls import path
from . import views

urlpatterns = [
    path('', views.encrypt, name='encrypt'),
]
