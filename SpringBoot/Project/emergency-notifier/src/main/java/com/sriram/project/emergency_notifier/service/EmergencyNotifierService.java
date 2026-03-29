package com.sriram.project.emergency_notifier.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sriram.project.emergency_notifier.dto.AlertRequest;
import com.sriram.project.emergency_notifier.dto.ContactRequest;
import com.sriram.project.emergency_notifier.dto.UserRegistrationRequest;
import com.sriram.project.emergency_notifier.entity.Contact;
import com.sriram.project.emergency_notifier.entity.User;
import com.sriram.project.emergency_notifier.repository.ContactRepository;
import com.sriram.project.emergency_notifier.repository.UserRepository;

@Service
@Transactional
public class EmergencyNotifierService {
    
    private static final Logger logger = LoggerFactory.getLogger(EmergencyNotifierService.class);
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private ContactRepository contactRepository;
    
    @Autowired
    private EmailService emailService;
    
    public String registerUser(UserRegistrationRequest request) {
        try {
            // Check if user already exists
            if (userRepository.existsByEmail(request.getEmail())) {
                return "User with this email already exists";
            }
            
            // Create and save user
            User user = new User();
            user.setName(request.getName());
            user.setEmail(request.getEmail());
            user.setPassword(request.getPassword()); // In production, hash this password
            
            User savedUser = userRepository.save(user);
            logger.info("User registered successfully: {}", savedUser.getEmail());
            
            // Save contacts
            if (request.getContacts() != null && !request.getContacts().isEmpty()) {
                List<Contact> contacts = new ArrayList<>();
                for (ContactRequest contactRequest : request.getContacts()) {
                    Contact contact = new Contact();
                    contact.setContactName(contactRequest.getContactName());
                    contact.setContactEmail(contactRequest.getContactEmail());
                    contact.setUser(savedUser);
                    contacts.add(contact);
                }
                contactRepository.saveAll(contacts);
                logger.info("Saved {} contacts for user: {}", contacts.size(), savedUser.getEmail());
            }
            
            return "User registered successfully";
            
        } catch (Exception e) {
            logger.error("Error registering user: {}", e.getMessage());
            return "Error registering user: " + e.getMessage();
        }
    }
    
    public String sendAlert(AlertRequest alertRequest) {
        try {
            // Find user by email
            Optional<User> userOptional = userRepository.findByEmail(alertRequest.getUserEmail());
            if (userOptional.isEmpty()) {
                return "User not found with email: " + alertRequest.getUserEmail();
            }
            
            User user = userOptional.get();
            List<Contact> contacts = contactRepository.findByUser(user);
            
            if (contacts.isEmpty()) {
                return "No emergency contacts found for user";
            }
            
            // Send alerts to all contacts
            int successCount = 0;
            for (Contact contact : contacts) {
                boolean emailSuccess = false;
                
                // Send Email - now using enhanced emergency alert template
                if (contact.getContactEmail() != null && !contact.getContactEmail().trim().isEmpty()) {
                    String locationUrl = "";
                    if (alertRequest.getLatitude() != null && alertRequest.getLongitude() != null) {
                        locationUrl = "https://maps.google.com/?q=" + 
                                    alertRequest.getLatitude() + "," + alertRequest.getLongitude();
                    }
                    
                    emailSuccess = emailService.sendEmergencyAlert(
                        contact.getContactEmail(),
                        user.getName(),
                        user.getEmail(),
                        alertRequest.getCustomMessage() != null ? alertRequest.getCustomMessage() : "I'm in danger! Please reach me immediately.",
                        locationUrl
                    );
                }
                
                if (emailSuccess) {
                    successCount++;
                }
            }
            
            logger.info("Alert sent to {}/{} contacts for user: {}", successCount, contacts.size(), user.getEmail());
            return String.format("Alert sent successfully to %d out of %d contacts", successCount, contacts.size());
            
        } catch (Exception e) {
            logger.error("Error sending alert: {}", e.getMessage());
            return "Error sending alert: " + e.getMessage();
        }
    }
    
    public List<Contact> getUserContacts(String userEmail) {
        Optional<User> userOptional = userRepository.findByEmail(userEmail);
        if (userOptional.isPresent()) {
            return contactRepository.findByUser(userOptional.get());
        }
        return new ArrayList<>();
    }
    
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}