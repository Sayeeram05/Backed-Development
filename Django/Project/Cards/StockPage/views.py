from django.shortcuts import render
from django.views import View
from .models import CardsStock


class StockPageView(View):
    def get(self, request):
        stocks = CardsStock.objects.all()
        print(stocks)
        print(stocks[0].card.card_code.item_code)
        return render(request, 'stockpage.html', {'stocks': stocks})

    def post(self, request):
       # Handle form submission
       return render(request, 'stockpage.html')
