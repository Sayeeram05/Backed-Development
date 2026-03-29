"""
Views for the WebSocket Restaurant App
"""

from django.shortcuts import render
from django.http import JsonResponse


def index(request):
    """
    Home page with WebSocket connection test interface
    """
    return render(request, 'index.html')


def websocket_test(request):
    """
    Simple endpoint to test server connectivity
    """
    return JsonResponse({
        'status': 'success',
        'message': 'WebSocket server is running',
        'endpoints': {
            'customer_websocket': 'ws://localhost:8000/ws/customer/',
            'owner_websocket': 'ws://localhost:8000/ws/owner/',
            'general_orders': 'ws://localhost:8000/ws/orders/'
        }
    })