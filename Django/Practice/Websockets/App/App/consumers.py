"""
WebSocket consumers for handling real-time order communication.
"""

import json
import datetime
from channels.generic.websocket import AsyncWebsocketConsumer


class OrderConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer to handle order communications between customers and owners.
    
    - Customers send order selections
    - Orders are broadcast to all connected owners in real-time
    """
    
    async def connect(self):
        """Accept WebSocket connection and add to owners group"""
        # Join the 'owners' group to receive order broadcasts
        await self.channel_layer.group_add("owners", self.channel_name)
        await self.accept()
        print(f"WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        """Leave the owners group when disconnecting"""
        await self.channel_layer.group_discard("owners", self.channel_name)
        print(f"WebSocket disconnected: {self.channel_name}")

    async def receive(self, text_data):
        """
        Receive message from WebSocket and broadcast to owners.
        
        Expected message format from customer:
        {
            "customer_id": "cust123",
            "item_name": "Mango Juice",
            "quantity": 2,
            "timestamp": "2023-10-05T10:30:00Z"
        }
        """
        try:
            data = json.loads(text_data)
            
            # Validate required fields
            required_fields = ['customer_id', 'item_name', 'quantity']
            if not all(field in data for field in required_fields):
                await self.send(text_data=json.dumps({
                    "error": "Missing required fields: customer_id, item_name, quantity"
                }))
                return
            
            # Add timestamp if not provided
            import datetime
            if 'timestamp' not in data:
                data['timestamp'] = datetime.datetime.now().isoformat()
            
            print(f"Received order: {data}")
            
            # Broadcast the order to all connected owners
            await self.channel_layer.group_send(
                "owners",
                {
                    "type": "order_message",
                    "message": data
                }
            )
            
            # Send confirmation back to customer
            await self.send(text_data=json.dumps({
                "status": "success",
                "message": "Order sent to owners"
            }))
            
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                "error": "Invalid JSON format"
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                "error": f"Server error: {str(e)}"
            }))

    async def order_message(self, event):
        """
        Send order message to WebSocket (called when message is broadcast to group).
        This method is called for each owner connected to the 'owners' group.
        """
        message = event["message"]
        await self.send(text_data=json.dumps({
            "type": "new_order",
            "data": message
        }))


class CustomerConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer specifically for customer connections.
    Customers use this to send orders and receive confirmations.
    """
    
    async def connect(self):
        """Accept customer WebSocket connection"""
        await self.accept()
        print(f"Customer WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        """Handle customer disconnection"""
        print(f"Customer WebSocket disconnected: {self.channel_name}")

    async def receive(self, text_data):
        """
        Handle order from customer and broadcast to owners.
        """
        try:
            data = json.loads(text_data)
            
            # Validate required fields
            required_fields = ['customer_id', 'item_name', 'quantity']
            if not all(field in data for field in required_fields):
                await self.send(text_data=json.dumps({
                    "error": "Missing required fields: customer_id, item_name, quantity"
                }))
                return
            
            # Add timestamp if not provided
            import datetime
            if 'timestamp' not in data:
                data['timestamp'] = datetime.datetime.now().isoformat()
            
            print(f"Customer order received: {data}")
            
            # Broadcast the order to all connected owners
            await self.channel_layer.group_send(
                "owners",
                {
                    "type": "order_message",
                    "message": data
                }
            )
            
            # Send confirmation back to customer
            await self.send(text_data=json.dumps({
                "status": "success",
                "message": "Order sent successfully",
                "order_id": f"order_{data['customer_id']}_{datetime.datetime.now().timestamp()}"
            }))
            
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                "error": "Invalid JSON format"
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                "error": f"Server error: {str(e)}"
            }))

    async def order_message(self, event):
        """
        Handle order messages (not typically used for customers,
        but included for completeness)
        """
        message = event["message"]
        await self.send(text_data=json.dumps({
            "type": "order_update",
            "data": message
        }))


class OwnerConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer specifically for owner connections.
    Owners use this to receive real-time order notifications.
    """
    
    async def connect(self):
        """Accept owner WebSocket connection and join owners group"""
        await self.channel_layer.group_add("owners", self.channel_name)
        await self.accept()
        print(f"Owner WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        """Remove owner from owners group when disconnecting"""
        await self.channel_layer.group_discard("owners", self.channel_name)
        print(f"Owner WebSocket disconnected: {self.channel_name}")

    async def receive(self, text_data):
        """
        Handle messages from owner (e.g., status updates, acknowledgments)
        """
        try:
            data = json.loads(text_data)
            print(f"Owner message received: {data}")
            
            # Handle different owner actions
            if data.get('action') == 'ping':
                await self.send(text_data=json.dumps({
                    "type": "pong",
                    "timestamp": datetime.datetime.now().isoformat()
                }))
            
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                "error": "Invalid JSON format"
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                "error": f"Server error: {str(e)}"
            }))

    async def order_message(self, event):
        """
        Send order message to owner WebSocket.
        This is called when a new order is broadcast to the owners group.
        """
        message = event["message"]
        await self.send(text_data=json.dumps({
            "type": "new_order",
            "data": message,
            "timestamp": message.get('timestamp', '')
        }))