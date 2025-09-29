from django.shortcuts import render
from django.views import View


class BillingPageView(View):
    template_name = 'billingpage.html'
    
    def get(self, request):
        return render(request, self.template_name)