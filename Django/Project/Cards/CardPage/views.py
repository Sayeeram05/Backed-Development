from django.shortcuts import redirect, render
from django.views import View

from StockPage.models import Item,CardsStock
from .models import Card

 

class CardPageView(View):
    template_name = 'cardpage.html'

    def get(self, request):
        cards = Card.objects.all()
        return render(request, self.template_name, {'cards': cards})
    
    def post(self, request):
        print(request.POST)
        return redirect('card_page')

class AddCardView(View):
    def post(self, request):        
        card_name = request.POST.get('card_name')
        category = request.POST.get('category')
        card_price = request.POST.get('card_price')
        supplier_name = request.POST.get('supplier_name')
        new_item = Item(
            item_name=card_name,
            item_type="card"
        )
        new_item.save()
        new_card = Card(
            card_code=new_item,
            card_name=card_name,
            category=category,
            card_price=card_price,
            supplier_name=supplier_name,
            added_by=request.user if request.user.is_authenticated else None
            
        )
        new_card.save()
        
        card_stock = CardsStock(
            card=new_card,
            stock_quantity=None,
            reorder_level=None,
            updated_by=request.user if request.user.is_authenticated else None
        )
        card_stock.save()
        return redirect('update_stock', stock_id=card_stock.id)
    


class UpdateCardView(View):
    template_name = 'cardpage.html'
    def post(self, request):
        button = request.POST.get('button')
        if button == 'update':
            cards = Card.objects.all()
            card_id = request.POST.get('card_id')
            update_card = Card.objects.get(id=card_id)
            card_name = update_card.card_name
            category = update_card.category
            card_price = update_card.card_price
            supplier_name = update_card.supplier_name
            context = {'button':'update', 'card_id': card_id, 'cardname': card_name, 'category': category, 'card_price': card_price, 'supplier_name': supplier_name, 'cards': cards}
            return render(request, self.template_name, context)
        
        elif button == 'update-changes':
            card_id = request.POST.get('card_id')
            update_card = Card.objects.get(id=card_id)
            update_card.card_name = request.POST.get('card_name')
            update_card.category = request.POST.get('category')
            update_card.card_price = request.POST.get('card_price')
            update_card.supplier_name = request.POST.get('supplier_name')
            update_card.save()
            return redirect('card_page')
        
        elif button == 'delete-request':
            print("Delete request received")
            card_id = request.POST.get('card_id')
            delete_card = Card.objects.get(id=card_id)
            return redirect('delete_card', card_code=delete_card.card_code.item_code)
        

class DeleteCardView(View):
    template_name = 'cardpage.html'
    def get(self, request, card_code):
        print("GET request:", request)
        cards = Card.objects.all()
        delete_card = Card.objects.get(card_code=card_code)
        context = {'cards': cards, 'delete_confirmation': 'True', 'delete_card_code': card_code, 'delete_card_name': delete_card.card_name, 'delete_card_category': delete_card.category, 'delete_card_price': delete_card.card_price}

        return render(request, self.template_name, context)
    
    def post(self, request, card_code):
        print("POST request:", request.POST)
        
        button = request.POST.get('button')
        if button == 'cancel':
            return redirect('card_page')
        elif button == 'confirm':
            item_card = Item.objects.get(item_code=card_code)
            item_card.delete()
            return redirect('card_page')

class SearchCardView(View):
    template_name = 'cardpage.html'
    print("SearchCardView initialized")
    def get(self, request):
        print(request.GET)
        column = request.GET.get('column', 'card_name')
        search_query = request.GET.get('search', '')
        print(f"Searching for {search_query} in column {column}")
        if column == 'card_price':
            cards = Card.objects.filter(card_price=search_query)
        elif search_query:
            cards = Card.objects.filter(**{f"{column}__icontains": search_query})
        else:
            cards = Card.objects.all()
        return render(request, self.template_name, {'cards': cards, 'search_query': search_query, 'selected_column': column})