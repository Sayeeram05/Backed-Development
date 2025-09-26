from django.conf import settings
from django.db import models
import uuid

def generate_item_code():
    code = uuid.uuid4().hex[:12]
    while(Item.objects.filter(item_code=code).exists()):
        code = uuid.uuid4().hex[:12]
    return code

class Item(models.Model):
    id = models.AutoField(primary_key=True)
    item_code = models.CharField(max_length=20, unique=True,default=generate_item_code, editable=False, blank=False, null=False)
    item_name = models.CharField(max_length=100,blank=False, null=False)
    item_type = models.CharField(max_length=100,blank=False, null=False)

    def __str__(self):
        return f"{self.item_name} ({self.item_code})"

# Create your models here.
class CardsStock(models.Model):
    id = models.AutoField(primary_key=True)
    card = models.OneToOneField('CardPage.Card', on_delete=models.CASCADE, related_name='stock')
    stock_quantity = models.IntegerField(default=None,blank=False,null=True)            # Current available stock
    reorder_level = models.IntegerField(default=None,blank=False,null=True)             # Low stock alert threshold    # e.g
    last_updated = models.DateTimeField(auto_now=True)           # Auto update on save
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    
    def __str__(self):
        return f"Stock for {self.card.card_name} ({self.card.card_code}) - Qty: {self.stock_quantity}"
    