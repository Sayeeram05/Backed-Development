from django.shortcuts import render, redirect
from .models import Task, Item


def home(request):
    tasks = Task.objects.all()
    context = {'tasks': tasks}
    return render(request, 'home.html', context)

def view_all_items(request, task_id):
    task = Task.objects.get(id=task_id)
    items = Item.objects.filter(task=task)
    context = {'task': task, 'items': items}
    return render(request, 'view_all_items.html', context)

def modify_item(request):
    if request.method == 'POST':
        operation = request.POST.get('button')
        print(operation)
        if(operation == 'update'):
            item_id = request.POST.get('item_id')
            item = Item.objects.get(id = item_id)
            item.description = request.POST.get('description')
            item.completed = 'completed' in request.POST
            item.save()
        elif(operation == 'delete'):
            item_id = request.POST.get('item_id')
            item = Item.objects.get(id = item_id)
            item.delete()
        
    return redirect(view_all_items, task_id=item.task.id)

def new_item(request):
    if request.method == 'POST':
        task_id = request.POST.get('task_id')
        task = Task.objects.get(id=task_id)
        
        description = request.POST.get('description')
        completed = 'completed' in request.POST
        
        Item.objects.create(task=task, description=description, completed=completed)
    return redirect('view_all_items', task_id=task.id)
        
def new_task(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        Task.objects.create(title=title)
    return redirect('home')    

def modify_task(request):
    if request.method == 'POST':
        operation = request.POST.get('button')
        print(operation)
        print(request.POST.get('title'))
        if(operation == 'update'):
            task_id = request.POST.get('task_id')
            task = Task.objects.get(id = task_id)
            task.title = request.POST.get('title')
            task.save()
        elif(operation == 'delete'):
            task_id = request.POST.get('task_id')
            task = Task.objects.get(id = task_id)
            task.delete()
        elif(operation == 'view'):
            task_id = request.POST.get('task_id')
            return redirect('view_all_items', task_id=task_id)
        
    return redirect('home')    


