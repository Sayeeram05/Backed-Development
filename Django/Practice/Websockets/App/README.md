# Restaurant WebSocket Real-Time Communication System

This project implements a real-time communication system for a restaurant using Django Channels (WebSocket) and Flutter apps for customers and owners.

## 🚀 Features

- **Real-time order transmission** from customer to owner
- **No database storage** - live data only
- **Multiple owner support** - all connected owners receive orders instantly
- **WebSocket-based communication** for low latency
- **Flutter mobile apps** for both customers and owners
- **Web-based test interface** for debugging

## 📁 Project Structure

```
App/
├── App/                    # Django backend
│   ├── settings.py        # Django settings with Channels config
│   ├── asgi.py           # ASGI configuration for WebSocket
│   ├── consumers.py      # WebSocket consumers
│   ├── routing.py        # WebSocket URL routing
│   ├── views.py          # HTTP views
│   └── urls.py           # HTTP URL routing
├── templates/
│   └── index.html        # Web test interface
├── customer/             # Flutter customer app
│   └── lib/main.dart     # Customer app implementation
└── owner/                # Flutter owner app
    └── lib/main.dart     # Owner dashboard implementation
```

## 🛠️ Setup Instructions

### 1. Django Backend Setup

First, install Django Channels:

```bash
pip install channels
```

The Django backend is already configured with:

- ✅ Channels added to `INSTALLED_APPS`
- ✅ ASGI application configured
- ✅ WebSocket consumers implemented
- ✅ URL routing setup

### 2. Start the Django Server

```bash
cd "App"
python manage.py runserver 0.0.0.0:8000
```

The server will be available at:

- HTTP: `http://localhost:8000`
- WebSocket: `ws://localhost:8000/ws/`

### 3. Flutter Apps Setup

For both customer and owner apps:

```bash
cd customer  # or cd owner
flutter pub get
flutter run
```

**Note**: Update the WebSocket URL in the Flutter apps if testing on physical devices:

- Replace `localhost:8000` with your computer's IP address
- Example: `ws://192.168.1.100:8000/ws/customer/`

## 🔌 WebSocket Endpoints

- `ws://localhost:8000/ws/customer/` - Customer orders endpoint
- `ws://localhost:8000/ws/owner/` - Owner notifications endpoint
- `ws://localhost:8000/ws/orders/` - General orders endpoint

## 📱 How to Test

### Method 1: Web Interface (Easiest)

1. Start Django server
2. Open `http://localhost:8000` in your browser
3. Click "Connect as Customer" and "Connect as Owner"
4. Use the customer interface to send orders
5. Watch orders appear instantly in the owner interface

### Method 2: Flutter Apps

1. Start Django server
2. Run customer Flutter app: `cd customer && flutter run`
3. Run owner Flutter app: `cd owner && flutter run`
4. Tap menu items in customer app to send orders
5. Watch orders appear instantly in owner dashboard

### Method 3: Manual WebSocket Testing

Use a WebSocket client to connect to:

```
ws://localhost:8000/ws/customer/
```

Send JSON order:

```json
{
  "customer_id": "test123",
  "item_name": "Pizza",
  "quantity": 2
}
```

## 📊 Data Format

### Customer → Server (Order)

```json
{
  "customer_id": "cust123",
  "item_name": "Mango Juice",
  "quantity": 2,
  "price": 3.5,
  "timestamp": "2023-10-05T10:30:00Z"
}
```

### Server → Owner (Notification)

```json
{
  "type": "new_order",
  "data": {
    "customer_id": "cust123",
    "item_name": "Mango Juice",
    "quantity": 2,
    "price": 3.5,
    "timestamp": "2023-10-05T10:30:00Z"
  }
}
```

## 🎯 Use Cases

1. **Customer App**: Restaurant customers select menu items and send orders
2. **Owner Dashboard**: Restaurant owners see real-time order notifications
3. **Multiple Locations**: Multiple owners can connect simultaneously
4. **Live Updates**: No page refresh needed - orders appear instantly

## 🔧 Troubleshooting

### WebSocket Connection Issues

- Ensure Django server is running on the correct port
- Check firewall settings for port 8000
- Update WebSocket URLs in Flutter apps for device testing

### Django Channels Issues

- Verify channels is installed: `pip show channels`
- Check Django logs for WebSocket connection attempts
- Ensure ASGI_APPLICATION is set correctly in settings.py

### Flutter Issues

- Run `flutter pub get` to install dependencies
- Check that `web_socket_channel` dependency is added
- Verify WebSocket URL format (ws:// not wss://)

## 🌟 Benefits

✅ **Real-time communication** - Orders appear instantly  
✅ **No database overhead** - Live data only  
✅ **Scalable** - Support multiple owners  
✅ **Lightweight** - Minimal server resources  
✅ **Mobile-first** - Native Flutter apps  
✅ **Web fallback** - Browser-based testing

## 🚀 Next Steps

- Add order acknowledgment from owners
- Implement order status updates
- Add customer authentication
- Create order history (if needed)
- Add push notifications for mobile apps
- Deploy to production with Redis channel layer
