from django.shortcuts import redirect, render
from django.views import View

from StockPage.models import Item,BagsStock
from .models import Bag

 

class BagPageView(View):
    template_name = 'bagpage.html'

    def get(self, request):
        bags = Bag.objects.all()
        return render(request, self.template_name, {'bags': bags})
    
    def post(self, request):
        print(request.POST)
        return redirect('bag_page')

class AddBagView(View):
    def post(self, request):        
        bag_name = request.POST.get('bag_name')
        category = request.POST.get('category')
        bag_price = request.POST.get('bag_price')
        supplier_name = request.POST.get('supplier_name')
        new_item = Item(
            item_name=bag_name,
            item_type="bag"
        )
        new_item.save()
        new_bag = Bag(
            bag_code=new_item,
            bag_name=bag_name,
            category=category,
            bag_price=bag_price,
            supplier_name=supplier_name,
            added_by=request.user if request.user.is_authenticated else None
            
        )
        new_bag.save()
        
        bag_stock = BagsStock(
            bag=new_bag,
            stock_quantity=None,
            reorder_level=None,
            updated_by=request.user if request.user.is_authenticated else None
        )
        bag_stock.save()
        return redirect('update_stock', stock_id=bag_stock.id)
    


class UpdateBagView(View):
    template_name = 'bagpage.html'
    def post(self, request):
        button = request.POST.get('button')
        if button == 'update':
            bags = Bag.objects.all()
            bag_id = request.POST.get('bag_id')
            updated_bag = Bag.objects.get(bag_id=bag_id)
            bag_name = updated_bag.bag_name
            category = updated_bag.category
            bag_price = updated_bag.bag_price
            supplier_name = updated_bag.supplier_name
            context = {'button':'update', 'bag_id': updated_bag.bag_id, 'bagname': bag_name, 'category': category, 'bag_price': bag_price, 'supplier_name': supplier_name, 'bags': bags}
            return render(request, self.template_name, context)
        
        elif button == 'update-changes':
            bag_id = request.POST.get('bag_id')
            updated_bag = Bag.objects.get(bag_id=bag_id)
            updated_bag.bag_name = request.POST.get('bag_name')
            updated_bag.category = request.POST.get('category')
            updated_bag.bag_price = request.POST.get('bag_price')
            updated_bag.supplier_name = request.POST.get('supplier_name')
            updated_bag.save()
            return redirect('bag_page')
        
        elif button == 'delete-request':
            print("Delete request received")
            bag_id = request.POST.get('bag_id')
            delete_bag = Bag.objects.get(bag_id=bag_id)
            return redirect('delete_bag', bag_code=delete_bag.bag_code.item_code)
        

class DeleteBagView(View):
    template_name = 'bagpage.html'
    def get(self, request, bag_code):
        print("GET request:", request)
        bags = Bag.objects.all()
        delete_bag = Bag.objects.get(bag_code=bag_code)
        context = {'bags': bags, 'delete_confirmation': 'True', 'delete_bag_code': bag_code, 'delete_bag_name': delete_bag.bag_name, 'delete_bag_category': delete_bag.category, 'delete_bag_price': delete_bag.bag_price}

        return render(request, self.template_name, context)
    
    def post(self, request, bag_code):
        print("POST request:", request.POST)
        
        button = request.POST.get('button')
        if button == 'cancel':
            return redirect('bag_page')
        elif button == 'confirm':
            delete_bag = Bag.objects.get(bag_code=bag_code)
            delete_bag.delete()
            return redirect('bag_page')

class SearchBagView(View):
    template_name = 'bagpage.html'
    print("SearchBagView initialized")
    def get(self, request):
        print(request.GET)
        column = request.GET.get('column', 'bag_name')
        search_query = request.GET.get('search', '')
        print(f"Searching for {search_query} in column {column}")
        if column == 'bag_price':
            bags = Bag.objects.filter(bag_price=search_query)
        elif search_query:
            bags = Bag.objects.filter(**{f"{column}__icontains": search_query})
        else:
            bags = Bag.objects.all()
        return render(request, self.template_name, {'bags': bags, 'search_query': search_query, 'selected_column': column})