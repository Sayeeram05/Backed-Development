from django.db import models

class BaseDataModel(models.Model):
    CompanyName = models.CharField(max_length=255)
    Description = models.CharField(max_length=500)
    PanNumber = models.CharField(max_length=50)
    Address = models.CharField(max_length=255)
    District = models.CharField(max_length=100)
    State = models.CharField(max_length=100)
    Pincode = models.CharField(max_length=20)
    PhoneNumber = models.CharField(max_length=20)
    AlternateMobileNumber = models.CharField(max_length=20, blank=True, null=True)
    Email = models.EmailField()
    TaxPercentage = models.DecimalField(max_digits=5, decimal_places=2)
    GstNumber = models.CharField(max_length=50, blank=True, null=True)