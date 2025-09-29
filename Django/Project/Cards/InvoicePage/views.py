from django.shortcuts import render
from django.views import View

class InvoicePageView(View):
    def get(self, request):
        return render(request, 'invoicepage.html', {})
