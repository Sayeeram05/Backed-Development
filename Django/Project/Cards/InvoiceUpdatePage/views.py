from django.shortcuts import render
from django.views import View

class InvoiceUpdateView(View):
    def get(self, request):
        return render(request, 'invoiceupdatepage.html')
