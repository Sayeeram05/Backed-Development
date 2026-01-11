// Main JavaScript for CyberX Platform
document.addEventListener('DOMContentLoaded', function() {
    // Remove loading bar after page load
    setTimeout(() => {
        const loadingBar = document.querySelector('.loading-bar');
        if (loadingBar) {
            loadingBar.style.display = 'none';
        }
    }, 2000);
    
    // Add parallax effect to cards (excluding email validation page)
    if (!window.location.pathname.includes('/email-validation/')) {
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                
                const centerX = rect.width / 2;
                const centerY = rect.height / 2;
                
                const rotateX = (y - centerY) / 10;
                const rotateY = (centerX - x) / 10;
                
                card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-5px)`;
            });
            
            card.addEventListener('mouseleave', () => {
                card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateY(0)';
            });
        });
    }
});