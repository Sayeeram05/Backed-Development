from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('Home.urls')),
    path('email-validation/', include('EmailValidation.urls')),
    path('url-threat-detection/', include('UrlThreadDetection.urls')),
]
