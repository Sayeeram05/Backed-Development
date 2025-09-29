document.addEventListener('DOMContentLoaded', function() {
    // Initialize variables
    let items = [];
    let subtotal = 0;
    const taxRate = 0.08;
    
    // DOM elements
    const itemTypeSelect = document.getElementById('item-type');
    const itemCodeSelect = document.getElementById('item-code');
    const itemQuantityInput = document.getElementById('item-quantity');
    const addItemButton = document.getElementById('add-item');
    const invoiceItemsContainer = document.getElementById('invoice-items');
    const subtotalElement = document.getElementById('subtotal');
    const taxElement = document.getElementById('tax');
    const totalElement = document.getElementById('total');
    const advancePaymentInput = document.getElementById('advance-payment');
    const remainingElement = document.getElementById('remaining');
    const paymentStatusElement = document.getElementById('payment-status');
    const printInvoiceButtons = document.querySelectorAll('#print-invoice, #print-invoice-bottom');
    const clearInvoiceButton = document.getElementById('clear-invoice');
    const saveInvoiceButton = document.getElementById('save-invoice');
    
    // Sample data - in a real app this would come from your database
    const inventory = {
        card: [
            { id: 'C001', name: 'Birthday Card - Floral', price: 4.99 },
            { id: 'C002', name: 'Wedding Congratulations', price: 5.99 },
            { id: 'C003', name: 'Thank You Card - Gold', price: 3.99 }
        ],
        bag: [
            { id: 'B001', name: 'Gift Bag - Medium Blue', price: 2.49 },
            { id: 'B002', name: 'Gift Bag - Large Red', price: 3.49 },
            { id: 'B003', name: 'Gift Bag - Small Pattern', price: 1.99 }
        ]
    };
    
    // Event listeners
    itemTypeSelect.addEventListener('change', populateItemCodes);
    addItemButton.addEventListener('click', addItemToInvoice);
    advancePaymentInput.addEventListener('input', updateRemaining);
    
    printInvoiceButtons.forEach(button => {
        button.addEventListener('click', printInvoice);
    });
    
    clearInvoiceButton.addEventListener('click', clearInvoice);
    
    // Initialize item codes dropdown
    function populateItemCodes() {
        const selectedType = itemTypeSelect.value;
        itemCodeSelect.innerHTML = '<option value="">Select Item</option>';
        
        if (selectedType) {
            inventory[selectedType].forEach(item => {
                const option = document.createElement('option');
                option.value = item.id;
                option.textContent = `${item.id} - ${item.name} ($${item.price.toFixed(2)})`;
                itemCodeSelect.appendChild(option);
            });
        }
    }
    
    // Add item to the invoice
    function addItemToInvoice() {
        const selectedType = itemTypeSelect.value;
        const selectedCode = itemCodeSelect.value;
        const quantity = parseInt(itemQuantityInput.value, 10) || 1;
        const manualPrice = parseFloat(document.getElementById('item-price').value);
        
        if (!selectedType || !selectedCode) {
            alert('Please select both item type and item code.');
            return;
        }
        
        // Find the selected item
        const selectedItem = inventory[selectedType].find(item => item.id === selectedCode);
        
        if (!selectedItem) return;
        
        // Use manual price if provided, otherwise use the default price
        const itemPrice = !isNaN(manualPrice) ? manualPrice : selectedItem.price;
        
        // Create unique ID for this line item
        const itemId = `item-${Date.now()}`;
        
        // Calculate item total
        const itemTotal = itemPrice * quantity;
        
        // Add to items array
        items.push({
            id: itemId,
            code: selectedItem.id,
            name: selectedItem.name,
            type: selectedType,
            price: itemPrice,
            quantity: quantity,
            total: itemTotal,
            isCustomPrice: !isNaN(manualPrice)
        });
        
        // Create row in table
        const row = document.createElement('tr');
        row.id = itemId;
        
        // Add a class if using custom price
        if (!isNaN(manualPrice)) {
            row.classList.add('custom-price-row');
        }
        
        row.innerHTML = `
            <td>${selectedItem.id}</td>
            <td>${selectedItem.name}</td>
            <td>${selectedType.charAt(0).toUpperCase() + selectedType.slice(1)}</td>
            <td>$${itemPrice.toFixed(2)}${!isNaN(manualPrice) ? '<small>*</small>' : ''}</td>
            <td>${quantity}</td>
            <td>$${itemTotal.toFixed(2)}</td>
            <td><button class="remove-item" data-id="${itemId}">Delete</button></td>
        `;
        
        invoiceItemsContainer.appendChild(row);
        
        // Add event listener to the remove button
        row.querySelector('.remove-item').addEventListener('click', function() {
            removeItem(itemId);
        });
        
        // Update totals
        updateTotals();
        
        // Reset selection fields
        itemQuantityInput.value = 1;
        document.getElementById('item-price').value = '';
    }
    
    // Remove item from the invoice
    function removeItem(itemId) {
        // Remove from DOM
        document.getElementById(itemId).remove();
        
        // Remove from items array
        items = items.filter(item => item.id !== itemId);
        
        // Update totals
        updateTotals();
    }
    
    // Update totals
    function updateTotals() {
        // Calculate subtotal
        subtotal = items.reduce((sum, item) => sum + item.total, 0);
        
        // Calculate tax
        const tax = subtotal * taxRate;
        
        // Calculate total
        const total = subtotal + tax;
        
        // Update display
        subtotalElement.textContent = `$${subtotal.toFixed(2)}`;
        taxElement.textContent = `$${tax.toFixed(2)}`;
        totalElement.textContent = `$${total.toFixed(2)}`;
        
        // Update remaining amount
        updateRemaining();
    }
    
    // Update remaining amount
    function updateRemaining() {
        const total = subtotal + (subtotal * taxRate);
        const advance = parseFloat(advancePaymentInput.value) || 0;
        const remaining = Math.max(0, total - advance);
        
        remainingElement.textContent = `$${remaining.toFixed(2)}`;
        
        // Update payment status
        if (advance <= 0) {
            paymentStatusElement.textContent = 'Unpaid';
            paymentStatusElement.className = 'status-badge';
        } else if (advance >= total) {
            paymentStatusElement.textContent = 'Paid';
            paymentStatusElement.className = 'status-badge paid';
        } else {
            paymentStatusElement.textContent = 'Partial Payment';
            paymentStatusElement.className = 'status-badge partial';
        }
    }
    
    // Print invoice
    function printInvoice() {
        window.print();
    }
    
    // Clear invoice
    function clearInvoice() {
        if (confirm('Are you sure you want to clear all items from this invoice?')) {
            // Clear items array
            items = [];
            
            // Clear table
            invoiceItemsContainer.innerHTML = '';
            
            // Reset totals
            subtotal = 0;
            updateTotals();
            
            // Reset form fields
            document.getElementById('customer-name').value = '';
            document.getElementById('customer-phone').value = '';
            document.getElementById('customer-email').value = '';
            document.getElementById('customer-address').value = '';
            document.getElementById('invoice-notes').value = '';
            advancePaymentInput.value = '0';
            
            // Reset item selection
            itemTypeSelect.value = '';
            itemCodeSelect.innerHTML = '<option value="">Select Item</option>';
            itemQuantityInput.value = 1;
        }
    }
    
    // Save invoice functionality would connect to your backend
    saveInvoiceButton.addEventListener('click', function() {
        // This would typically be an AJAX request to your server
        alert('Invoice saved successfully!');
        
        // Generate a new invoice number for the next invoice
        const invoiceNum = document.getElementById('invoice-number');
        const currentNum = parseInt(invoiceNum.textContent.split('-')[2]);
        invoiceNum.textContent = `INV-2025-${String(currentNum + 1).padStart(4, '0')}`;
    });
    
    // Set today's date
    document.getElementById('delivery-date').valueAsDate = new Date();
});