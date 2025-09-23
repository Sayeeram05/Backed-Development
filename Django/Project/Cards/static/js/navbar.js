document.addEventListener('DOMContentLoaded', function() {
            const hamburger = document.querySelector('.hamburger');
            const navLinks = document.querySelector('.nav-links');
            
            // Toggle navigation menu
            hamburger.addEventListener('click', function() {
                navLinks.classList.toggle('nav-active');
                hamburger.classList.toggle('toggle');
            });
            
            // Close menu when clicking a link (mobile)
            document.querySelectorAll('.nav-links a').forEach(link => {
                link.addEventListener('click', () => {
                    if (navLinks.classList.contains('nav-active')) {
                        navLinks.classList.remove('nav-active');
                        hamburger.classList.remove('toggle');
                    }
                });
            });
        });