document.addEventListener('DOMContentLoaded', function() {
    // Form visibility toggle
    const addBagButton = document.getElementById('add-bag-button');
    const bagFormContainer = document.getElementById('bag-form-container');
    const formCloseButton = document.getElementById('form-close');
    
    if (addBagButton && bagFormContainer) {
        addBagButton.addEventListener('click', function() {
            bagFormContainer.classList.add('visible');
        });
        
        if (formCloseButton) {
            formCloseButton.addEventListener('click', function() {
                bagFormContainer.classList.remove('visible');
            });
        }
    }
    
    // Table sorting functionality
    const table = document.querySelector('.bag-table');
    if (table) {
        const headers = table.querySelectorAll('th');
        const tableBody = table.querySelector('tbody');
        let currentSortCol = null;
        let currentSortOrder = 'asc';
        
        headers.forEach((header, index) => {
            // Skip action column
            if (!header.classList.contains('col-actions')) {
                header.addEventListener('click', () => {
                    // Remove sort indicators from all headers
                    headers.forEach(h => {
                        h.classList.remove('sort-asc', 'sort-desc');
                    });
                    
                    // Determine sort order
                    if (currentSortCol === index) {
                        currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
                    } else {
                        currentSortCol = index;
                        currentSortOrder = 'asc';
                    }
                    
                    // Add sort indicator
                    header.classList.add(`sort-${currentSortOrder}`);
                    
                    // Sort table
                    const rows = Array.from(tableBody.querySelectorAll('tr'));
                    
                    rows.sort((a, b) => {
                        const cellA = a.querySelectorAll('td')[index].textContent.trim();
                        const cellB = b.querySelectorAll('td')[index].textContent.trim();
                        
                        // Check if the content is a date
                        const dateA = new Date(cellA);
                        const dateB = new Date(cellB);
                        
                        if (!isNaN(dateA) && !isNaN(dateB)) {
                            return currentSortOrder === 'asc' 
                                ? dateA - dateB 
                                : dateB - dateA;
                        }
                        
                        // Check if the content is a number
                        const numA = parseFloat(cellA.replace(/[^0-9.-]+/g, ''));
                        const numB = parseFloat(cellB.replace(/[^0-9.-]+/g, ''));
                        
                        if (!isNaN(numA) && !isNaN(numB)) {
                            return currentSortOrder === 'asc' 
                                ? numA - numB 
                                : numB - numA;
                        }
                        
                        // String comparison
                        return currentSortOrder === 'asc' 
                            ? cellA.localeCompare(cellB) 
                            : cellB.localeCompare(cellA);
                    });
                    
                    // Remove existing rows
                    rows.forEach(row => row.remove());
                    
                    // Append sorted rows
                    rows.forEach(row => tableBody.appendChild(row));
                });
            }
        });
    }
    
    
});