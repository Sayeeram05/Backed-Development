from django.shortcuts import redirect, render
from django.views import View
from .models import CardsStock


class StockPageView(View):
    template_name = 'stockpage.html'
    
    def get(self, request):
        stocks = CardsStock.objects.all()
        print(stocks)
        print(stocks[0].card.card_code.item_code)
        return render(request, self.template_name, {'stocks': stocks})

    def post(self, request):
       # Handle form submission
       return render(request, self.template_name)

class ModifyStockView(View):
    def post(self, request):
        button = request.POST.get('button')
        if(button == 'delete'):
            stock_id = request.POST.get('stock_id')
            stock = CardsStock.objects.get(id=stock_id)
            stock.stock_quantity = None
            stock.reorder_level = None
            stock.save()
        
        if(button == 'update'):
            stock_id = request.POST.get('stock_id')
            print(stock_id)
            return redirect('update_stock', stock_id=stock_id)
        print(request.POST)
        return redirect('stock_page')

class UpdateStockView(View):
    template_name = 'stockpage.html'
    
    def get(self, request, stock_id):
        stocks = CardsStock.objects.all()
        update_stock = CardsStock.objects.get(id=stock_id)
        context = {'stocks': stocks, 
                   'update_stock': update_stock, 
                   'card': update_stock.card, 'update': True, 
                   'stock_id': stock_id, 
                   'card_id': update_stock.card.id}
        return render(request, self.template_name, context)

    def post(self, request, stock_id):
        stock = CardsStock.objects.get(id=stock_id)
        stock_quantity = request.POST.get('stock_quantity')
        reorder_level = request.POST.get('reorder_level')
        stock.stock_quantity = stock_quantity
        stock.reorder_level = reorder_level
        stock.updated_by = request.user
        stock.save()
        return redirect('stock_page')
