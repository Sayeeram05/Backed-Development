from django.shortcuts import redirect, render
from django.views import View
from .models import CardsStock, BagsStock
from CardPage.models import Card
from BagPage.models import Bag
class StockPageView(View):
    template_name = 'stockpage.html'
    
    def get(self, request):
        print(request.GET)
        
        current_view = request.GET.get('view')
        if current_view not in ['cards', 'bags'] or current_view == 'cards':  
            current_view = 'cards'
            stocks = CardsStock.objects.all()
            context = {'stocks': stocks, 'current_view': current_view}
            return render(request, self.template_name, context)
        elif current_view == 'bags':
            return redirect('bags_stock')  


class ModifyStockView(View):
    def post(self, request):
        print(request.POST)
        view = request.POST.get('view')
        if view not in ['cards', 'bags'] or view == 'cards':
            view = 'cards'
            button = request.POST.get('button')
            if(button == 'delete'):
                card_id = request.POST.get('card_id')
                stock = CardsStock.objects.get(card_id=card_id)
                stock.stock_quantity = None
                stock.reorder_level = None
                stock.save()
                return redirect('stock_page')  # Specify view=cards
            elif(button == 'update'):
                card_id = request.POST.get('card_id')
                return redirect('update_card_stock', stock_id=card_id)
            
        elif view == 'bags':
            button = request.POST.get('button')
            if(button == 'delete'):
                bag_id = request.POST.get('bag_id')
                # Fixed typo: bad_id → bag_id
                stock = BagsStock.objects.get(bag_id=bag_id)
                stock.stock_quantity = None
                stock.reorder_level = None
                stock.save()
                return redirect('stock_page', view='bags')  # Specify view=bags
            elif(button == 'update'):
                bag_id = request.POST.get('bag_id')
                return redirect('update_bag_stock', stock_id=bag_id)

            
class UpdateCardStockView(View):
    template_name = 'stockpage.html'
    print("In UpdateCardStockView\n\n\n")
    def get(self, request, stock_id):

        stocks = CardsStock.objects.all()
        update_stock = CardsStock.objects.get(card_id=stock_id)
        print(update_stock)
        context = {'stocks': stocks,
                    'update_stock': update_stock,
                    'card': update_stock.card, 'update': True,
                    'stock_id': stock_id,
                    'card_id': update_stock.card.card_id,
                    'current_view': 'cards'}
        return render(request, self.template_name, context)

    def post(self, request, stock_id):
        stock = CardsStock.objects.get(card_id=stock_id)
        stock_quantity = request.POST.get('stock_quantity')
        reorder_level = request.POST.get('reorder_level')
        stock.stock_quantity = stock_quantity
        stock.reorder_level = reorder_level
        stock.updated_by = None if not request.user.is_authenticated else request.user
        stock.save()
        return redirect('stock_page') 

class BagsStockView(View):
    template_name = 'stockpage.html'
    
    def get(self, request):
        print(request.GET)
        
        current_view = 'bags'
        stocks = BagsStock.objects.all()
        context = {'stocks': stocks, 'current_view': current_view}
        return render(request, self.template_name, context)
class UpdateBagStockView(View):
    template_name = 'stockpage.html'
    print("In UpdateBagStockView\n\n\n")
    
    def get(self, request, stock_id):
        stocks = BagsStock.objects.all()
        update_stock = BagsStock.objects.get(bag_id=stock_id)
        context = {'stocks': stocks, 
                'update_stock': update_stock, 
                'bag': update_stock.bag, 'update': True, 
                'stock_id': stock_id, 
                'bag_id': update_stock.bag.bag_id,
                'current_view': 'bags'}
        return render(request, self.template_name, context)

    def post(self, request, stock_id):
        print("In POST of UpdateStockView")
        print(request.POST)
        stock = BagsStock.objects.get(bag_id=stock_id)
        stock_quantity = request.POST.get('stock_quantity')
        reorder_level = request.POST.get('reorder_level')
        stock.stock_quantity = stock_quantity
        stock.reorder_level = reorder_level
        stock.updated_by =  None if not request.user.is_authenticated else request.user
        stock.save()
        return redirect('bags_stock')  # Specify view=bags

class SearchCardView(View):
    template_name = 'stockpage.html'
    print("SearchCardView initialized")
    def get(self, request):
        print(request.GET)
        column = request.GET.get('column', 'card_name')
        search_query = request.GET.get('search', '')
        print(f"Searching for {search_query} in column {column}")
        if search_query == '-' and column in ['stock_quantity', 'reorder_level','updated_by__username']:
            cards = CardsStock.objects.filter(**{f"{column}__isnull": True})  
        
        elif column =='card_name':
            
            cards = CardsStock.objects.filter(**{"card__card_name__icontains": search_query})
        elif column == 'card_code':
            cards = CardsStock.objects.filter(**{"card__card_code__item_code__icontains": search_query})
        elif column == 'card_price':
            cards = CardsStock.objects.filter(**{"card__card_price": search_query})
        elif column in ['stock_quantity', 'reorder_level', 'updated_by__username']:
            filter_kwargs = {f"{column}": search_query}
            cards = CardsStock.objects.filter(**filter_kwargs)
        else:
            cards = CardsStock.objects.all()

        return render(request, self.template_name, {'current_view': 'cards', 'stocks': cards, 'search_query': search_query, 'selected_column': column})

class SearchBagView(View):
    template_name = 'stockpage.html'
    print("SearchBagView initialized")
    def get(self, request):
        print(request.GET)
        column = request.GET.get('column', 'bag_name')
        search_query = request.GET.get('search', '')
        print(f"Searching for {search_query} in column {column}")
        if search_query == '-' and column in ['stock_quantity', 'reorder_level','updated_by__username']:
            bags = BagsStock.objects.filter(**{f"{column}__isnull": True})  
        
        elif column =='bag_name':
            bags = BagsStock.objects.filter(**{"bag__bag_name__icontains": search_query})
        elif column == 'bag_code':
            bags = BagsStock.objects.filter(**{"bag__bag_code__item_code__icontains": search_query})
        elif column == 'bag_price':
            bags = BagsStock.objects.filter(**{"bag__bag_price": search_query})
        elif column in ['stock_quantity', 'reorder_level', 'updated_by__username']:
            filter_kwargs = {f"{column}": search_query}
            bags = BagsStock.objects.filter(**filter_kwargs)
        else:
            bags = BagsStock.objects.all()

        return render(request, self.template_name, {'current_view': 'bags', 'stocks': bags, 'search_query': search_query, 'selected_column': column})