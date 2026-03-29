"""
WebSocket URL routing configuration for the App project.
"""

from django.urls import path
from . import consumers

# WebSocket URL patterns
websocket_urlpatterns = [
    # General order endpoint (can be used by both customers and owners)
    path('ws/orders/', consumers.OrderConsumer.as_asgi()),
    
    # Specific endpoints for different user types
    path('ws/customer/', consumers.CustomerConsumer.as_asgi()),
    path('ws/owner/', consumers.OwnerConsumer.as_asgi()),
]