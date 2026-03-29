// Global variables
let contactCount = 1;
const API_BASE_URL = 'http://localhost:8080';

// DOM Elements
const registrationSection = document.getElementById('registration-section');
const alertSection = document.getElementById('alert-section');
const messageDiv = document.getElementById('message');
const registrationForm = document.getElementById('registration-form');
const alertForm = document.getElementById('alert-form');
const userInfo = document.getElementById('user-info');

// Initialize the app
document.addEventListener('DOMContentLoaded', function () {
    showRegistration();
    setupEventListeners();
    requestLocationPermission();
});

// Event Listeners
function setupEventListeners() {
    registrationForm.addEventListener('submit', handleRegistration);
    alertForm.addEventListener('submit', handleAlert);

    // Navigation button styling
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
        });
    });

    // Auto-location setup
    document.getElementById('include-location').addEventListener('change', function () {
        if (this.checked) {
            requestLocationPermission();
        }
    });
}

// Navigation Functions
function showRegistration() {
    registrationSection.classList.remove('hidden');
    alertSection.classList.add('hidden');
    hideMessage();
}

function showAlert() {
    registrationSection.classList.add('hidden');
    alertSection.classList.remove('hidden');
    hideMessage();
}

// Auto-location permission request
function requestLocationPermission() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
            function (position) {
                showLocationStatus('Location ready ✓', 'success');
            },
            function (error) {
                showLocationStatus('Location unavailable', 'error');
            }
        );
    }
}

function showLocationStatus(message, type) {
    const statusDiv = document.getElementById('location-status');
    const statusText = document.getElementById('location-text');
    statusText.textContent = message;
    statusDiv.className = `location-status ${type}`;
    statusDiv.classList.remove('hidden');

    setTimeout(() => {
        statusDiv.classList.add('hidden');
    }, 3000);
}

// Contact Management
function addContact() {
    contactCount++;
    const contactsContainer = document.getElementById('contacts-container');

    const contactDiv = document.createElement('div');
    contactDiv.className = 'contact-group';
    contactDiv.innerHTML = `
        <h4>Contact ${contactCount} <button type="button" onclick="removeContact(this)" class="remove-btn" style="float: right; background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer;">Remove</button></h4>
        <div class="form-group">
            <label for="contact-name-${contactCount}">Contact Name:</label>
            <input type="text" id="contact-name-${contactCount}" name="contact-name-${contactCount}" required>
        </div>
        <div class="form-group">
            <label for="contact-email-${contactCount}">Contact Email:</label>
            <input type="email" id="contact-email-${contactCount}" name="contact-email-${contactCount}" required>
        </div>
    `;

    contactsContainer.appendChild(contactDiv);
}

function removeContact(button) {
    button.closest('.contact-group').remove();
}

// Registration Handler
async function handleRegistration(event) {
    event.preventDefault();

    const formData = new FormData(registrationForm);

    // Collect user data
    const userData = {
        name: formData.get('name'),
        email: formData.get('email'),
        password: formData.get('password'),
        contacts: []
    };

    // Collect contacts data
    const contactGroups = document.querySelectorAll('.contact-group');
    contactGroups.forEach((group, index) => {
        const contactNumber = index + 1;
        const contactName = formData.get(`contact-name-${contactNumber}`);
        const contactEmail = formData.get(`contact-email-${contactNumber}`);

        if (contactName && contactEmail) {
            userData.contacts.push({
                contactName: contactName,
                contactEmail: contactEmail
            });
        }
    });

    try {
        showLoading(event.target.querySelector('button[type="submit"]'));

        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
            showMessage(result.message, 'success');
            registrationForm.reset();
            contactCount = 1;
            // Reset contacts container to show only one contact
            document.getElementById('contacts-container').innerHTML = `
                <div class="contact-group">
                    <h4>Contact 1</h4>
                    <div class="form-group">
                        <label for="contact-name-1">Contact Name:</label>
                        <input type="text" id="contact-name-1" name="contact-name-1" required>
                    </div>
                    <div class="form-group">
                        <label for="contact-email-1">Contact Email:</label>
                        <input type="email" id="contact-email-1" name="contact-email-1" required>
                    </div>
                </div>
            `;
        } else {
            showMessage(result.message, 'error');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showMessage('Error connecting to server. Please try again.', 'error');
    } finally {
        hideLoading(event.target.querySelector('button[type="submit"]'));
    }
}

// Alert Handler
async function handleAlert(event) {
    event.preventDefault();

    const formData = new FormData(alertForm);
    const userEmail = formData.get('alert-email');
    const customMessage = formData.get('custom-message');
    const includeLocation = document.getElementById('include-location').checked;

    const alertData = {
        userEmail: userEmail,
        customMessage: customMessage || 'I need immediate assistance!'
    };

    // Auto-get location if enabled
    if (includeLocation) {
        try {
            showLocationStatus('Getting location...', 'info');
            const position = await getCurrentPosition();
            alertData.latitude = position.coords.latitude;
            alertData.longitude = position.coords.longitude;
            showLocationStatus('Location obtained ✓', 'success');
        } catch (error) {
            console.warn('Could not get location:', error);
            showLocationStatus('Location unavailable', 'error');
        }
    }

    try {
        showLoading(event.target.querySelector('button[type="submit"]'));

        // First, get user info to display
        await loadUserInfo(userEmail);

        // Send the alert
        const response = await fetch(`${API_BASE_URL}/alert`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(alertData)
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
            showMessage('🚨 Emergency alert sent successfully! Your contacts have been notified via email.', 'success');
        } else {
            showMessage(result.message, 'error');
        }
    } catch (error) {
        console.error('Alert error:', error);
        showMessage('Error connecting to server. Please try again.', 'error');
    } finally {
        hideLoading(event.target.querySelector('button[type="submit"]'));
    }
}

// Load User Info
async function loadUserInfo(email) {
    try {
        // Get user details
        const userResponse = await fetch(`${API_BASE_URL}/user/${encodeURIComponent(email)}`);
        if (userResponse.ok) {
            const user = await userResponse.json();
            document.getElementById('user-name').textContent = user.name;
        }

        // Get user contacts
        const contactsResponse = await fetch(`${API_BASE_URL}/user/${encodeURIComponent(email)}/contacts`);
        if (contactsResponse.ok) {
            const contacts = await contactsResponse.json();
            displayContacts(contacts);
            userInfo.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Error loading user info:', error);
    }
}

// Display Contacts
function displayContacts(contacts) {
    const contactsList = document.getElementById('contacts-list');
    contactsList.innerHTML = '';

    contacts.forEach((contact, index) => {
        const contactDiv = document.createElement('div');
        contactDiv.className = 'contact-item';
        contactDiv.innerHTML = `
            <h4>${contact.contactName}</h4>
            <p><strong>Email:</strong> ${contact.contactEmail}</p>
        `;
        contactsList.appendChild(contactDiv);
    });
}

// Geolocation Helper
function getCurrentPosition() {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error('Geolocation is not supported by this browser.'));
            return;
        }

        navigator.geolocation.getCurrentPosition(resolve, reject, {
            enableHighAccuracy: true,
            timeout: 10000,
            maximumAge: 60000
        });
    });
}

// UI Helper Functions
function showMessage(message, type) {
    messageDiv.innerHTML = message;
    messageDiv.className = `message ${type}`;
    messageDiv.classList.remove('hidden');

    // Auto hide after 7 seconds for success, 5 for error
    setTimeout(() => {
        hideMessage();
    }, type === 'success' ? 7000 : 5000);
}

function hideMessage() {
    messageDiv.classList.add('hidden');
}

function showLoading(button) {
    const originalText = button.textContent;
    button.innerHTML = '<span class="loading"></span>Sending...';
    button.disabled = true;
    button.dataset.originalText = originalText;
}

function hideLoading(button) {
    button.textContent = button.dataset.originalText;
    button.disabled = false;
}

// Input Validation
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Add real-time validation
document.addEventListener('DOMContentLoaded', function () {
    // Email validation
    document.querySelectorAll('input[type="email"]').forEach(input => {
        input.addEventListener('blur', function () {
            if (this.value && !validateEmail(this.value)) {
                this.style.borderColor = '#dc3545';
                showMessage('Please enter a valid email address', 'error');
            } else {
                this.style.borderColor = '#e9ecef';
            }
        });
    });
});