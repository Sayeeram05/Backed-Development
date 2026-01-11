// Email Validation JavaScript - Animation & UI Effects Only
class EmailValidationUI {
    constructor() {
        this.emailInput = document.getElementById('emailInput');
        this.clearInput = document.getElementById('clearInput');
        this.helperText = document.getElementById('helperText');
        this.validateBtn = document.getElementById('validateBtn');
        this.validationForm = document.getElementById('emailValidationForm');
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.addVisualEffects();
    }
    
    bindEvents() {
        // Email input events for UI feedback only
        this.emailInput.addEventListener('input', (e) => this.onEmailInput(e));
        this.emailInput.addEventListener('focus', (e) => this.onInputFocus(e));
        this.emailInput.addEventListener('blur', (e) => this.onInputBlur(e));
        
        // Clear input button
        this.clearInput.addEventListener('click', () => this.clearEmailInput());
        
        // Form submission animation
        this.validationForm.addEventListener('submit', (e) => this.onFormSubmit(e));
        
        // Enter key animation
        this.emailInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.animateButton();
            }
        });
    }
    
    onEmailInput(e) {
        const email = e.target.value.trim();
        const inputContainer = this.emailInput.parentElement;
        
        // Simple UI feedback only - no validation logic
        if (!email) {
            inputContainer.classList.remove('valid', 'invalid', 'active');
            this.helperText.textContent = 'Enter an email address to perform comprehensive validation';
            this.helperText.className = 'helper-text';
            this.clearInput.style.opacity = '0';
        } else {
            inputContainer.classList.add('active');
            this.helperText.textContent = 'Ready for validation';
            this.helperText.className = 'helper-text success';
            this.clearInput.style.opacity = '1';
        }
        
        // Animate input container
        this.animateInputContainer(inputContainer);
    }
    
    onInputFocus(e) {
        const inputContainer = this.emailInput.parentElement;
        inputContainer.classList.add('focused');
        this.animateFocusEffect();
    }
    
    onInputBlur(e) {
        const inputContainer = this.emailInput.parentElement;
        inputContainer.classList.remove('focused');
    }
    
    onFormSubmit(e) {
        // Show loading animation
        this.showLoadingAnimation();
        
        // The form will submit normally and redirect to show results
        // Scroll will be handled on the results page load
        console.log('Form is being submitted with email:', this.emailInput.value);
    }
    
    clearEmailInput() {
        // Clear input with animation
        this.emailInput.style.transform = 'scale(0.95)';
        setTimeout(() => {
            this.emailInput.value = '';
            this.emailInput.style.transform = 'scale(1)';
            this.emailInput.focus();
            
            // Reset UI states
            const inputContainer = this.emailInput.parentElement;
            inputContainer.classList.remove('valid', 'invalid', 'active');
            this.helperText.textContent = 'Enter an email address to perform comprehensive validation';
            this.helperText.className = 'helper-text';
            this.clearInput.style.opacity = '0';
        }, 100);
    }
    
    showLoadingAnimation() {
        // Simple loading animation without problematic effects
        const btnText = this.validateBtn.querySelector('.btn-text');
        const btnSpinner = this.validateBtn.querySelector('.btn-spinner');
        
        if (btnText && btnSpinner) {
            btnText.style.display = 'none';
            btnSpinner.style.display = 'flex';
            this.validateBtn.disabled = true;
        }
    }
    
    addVisualEffects() {
        // Disable any tilt/transform effects on email validation page
        this.disableTiltEffects();
        
        // Add initial transition styles for suggestions dropdown
        if (this.emailSuggestions) {
            this.emailSuggestions.style.opacity = '0';
            this.emailSuggestions.style.transform = 'translateY(-10px)';
            this.emailSuggestions.style.transition = 'all 0.2s ease';
        }
        
        // Initialize other visual elements
        this.initializeVisualElements();
    }
    
    disableTiltEffects() {
        // Find all cards and disable any transform effects
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            // Remove any existing event listeners that might cause tilt effects
            card.style.transform = 'none';
            card.style.transition = 'all 0.2s ease';
            
            // Override any hover effects that might be problematic
            card.addEventListener('mouseenter', (e) => {
                e.target.style.transform = 'none';
            });
            
            card.addEventListener('mousemove', (e) => {
                e.target.style.transform = 'none';
            });
            
            card.addEventListener('mouseleave', (e) => {
                e.target.style.transform = 'none';
            });
        });
    }
    
    initializeVisualElements() {
        // Setup any initial visual states without problematic animations
        const inputContainer = this.emailInput.parentElement;
        if (inputContainer) {
            inputContainer.style.transition = 'all 0.2s ease';
        }
        
        if (this.clearInput) {
            this.clearInput.style.transition = 'all 0.2s ease';
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    new EmailValidationUI();
    
    // Check if results are present and scroll to Email Security Validator
    const hasResults = document.querySelector('.alert') || document.querySelector('.results-section[style*="block"]');
    
    if (hasResults) {
        // Small delay to ensure all content is rendered
        setTimeout(() => {
            const emailValidator = document.getElementById('emailSecurityValidator');
            if (emailValidator) {
                emailValidator.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center'
                });
            }
        }, 300);
    }
});