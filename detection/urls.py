"""
URL configuration for the detection application.
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('detect/', views.detect_threat, name='detect_threat'),
    path('result/', views.result_view, name='result_view'),
    path('about/', views.about, name='about'),
]
