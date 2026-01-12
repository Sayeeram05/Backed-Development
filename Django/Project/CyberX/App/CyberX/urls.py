from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('Home.urls')),
    path('emailvalidation/', include('EmailValidation.urls')),
    path('urlthreatdetection/', include('UrlThreadDetection.urls')),
    path('phishingdetection/', include('PhisingDetection.urls')),
]
