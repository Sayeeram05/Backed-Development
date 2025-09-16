from django.db import models

# Create your models here.
class Task(models.Model):
    title = models.CharField(max_length=200)

    def __str__(self):
        return self.title

class Item(models.Model):
    task = models.ForeignKey(Task, related_name='items', on_delete=models.CASCADE)
    description = models.CharField(max_length=300)
    completed = models.BooleanField(default=False)

    def __str__(self):
        return self.description