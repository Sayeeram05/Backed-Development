from django.db import models
from django.conf import settings


class Card(models.Model):
    id = models.AutoField(primary_key=True)
    card_code = models.ForeignKey('StockPage.Item', to_field='item_code', on_delete=models.CASCADE, related_name='cards')
    card_name = models.CharField(max_length=100, blank=False, null=False)
    category = models.CharField(max_length=50, default='greeting', blank=False, null=False)
    card_price = models.DecimalField(max_digits=10, decimal_places=2, blank=False, null=False)
    supplier_name = models.CharField(max_length=100, blank=True, null=True)
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.card_name} ({self.card_code})"
