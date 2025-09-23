from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    
    role_choices = (
        (0, 'Admin'),
        (1, 'Manager'),
        (2, 'Staff'),
    )
    
    role = models.PositiveSmallIntegerField(choices=role_choices, default=2)
