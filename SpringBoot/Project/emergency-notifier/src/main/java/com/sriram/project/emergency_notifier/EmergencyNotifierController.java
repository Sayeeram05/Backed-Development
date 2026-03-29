package com.sriram.project.emergency_notifier;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sriram.project.emergency_notifier.dto.AlertRequest;
import com.sriram.project.emergency_notifier.dto.UserRegistrationRequest;
import com.sriram.project.emergency_notifier.entity.Contact;
import com.sriram.project.emergency_notifier.entity.User;
import com.sriram.project.emergency_notifier.service.EmailService;
import com.sriram.project.emergency_notifier.service.EmergencyNotifierService;

import jakarta.validation.Valid;

@RestController
@CrossOrigin(origins = "*")
public class EmergencyNotifierController {
    
    private static final Logger logger = LoggerFactory.getLogger(EmergencyNotifierController.class);
    
    @Autowired
    private EmergencyNotifierService emergencyNotifierService;
    
    @Autowired
    private EmailService emailService;
    
    @GetMapping("/status")
    public ResponseEntity<Map<String, String>> getStatus() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "Emergency Notifier is running - Email Only Mode");
        response.put("timestamp", String.valueOf(System.currentTimeMillis()));
        response.put("service", "Email Emergency Alerts");
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> registerUser(@Valid @RequestBody UserRegistrationRequest request) {
        logger.info("Registering user: {}", request.getEmail());
        
        String result = emergencyNotifierService.registerUser(request);
        
        Map<String, String> response = new HashMap<>();
        if (result.equals("User registered successfully")) {
            response.put("status", "success");
            response.put("message", result);
            return ResponseEntity.ok(response);
        } else {
            response.put("status", "error");
            response.put("message", result);
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    @PostMapping("/alert")
    public ResponseEntity<Map<String, String>> sendAlert(@Valid @RequestBody AlertRequest alertRequest) {
        logger.info("Sending emergency email alert for user: {}", alertRequest.getUserEmail());
        
        String result = emergencyNotifierService.sendAlert(alertRequest);
        
        Map<String, String> response = new HashMap<>();
        if (result.contains("successfully")) {
            response.put("status", "success");
            response.put("message", "🚨 Emergency alert sent successfully via email! Your contacts have been notified.");
            return ResponseEntity.ok(response);
        } else {
            response.put("status", "error");
            response.put("message", result);
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    @GetMapping("/user/{email}/contacts")
    public ResponseEntity<List<Contact>> getUserContacts(@PathVariable String email) {
        logger.info("Getting contacts for user: {}", email);
        
        List<Contact> contacts = emergencyNotifierService.getUserContacts(email);
        return ResponseEntity.ok(contacts);
    }
    
    @GetMapping("/user/{email}")
    public ResponseEntity<User> getUserByEmail(@PathVariable String email) {
        logger.info("Getting user info for: {}", email);
        
        Optional<User> userOptional = emergencyNotifierService.getUserByEmail(email);
        if (userOptional.isPresent()) {
            return ResponseEntity.ok(userOptional.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    
    @GetMapping("/test-email")
    public ResponseEntity<String> testEmail(@RequestParam String email) {
        logger.info("Testing email to: {}", email);
        
        boolean success = emailService.sendEmergencyAlert(
            email,
            "Test User",
            "test@emergency-notifier.com",
            "This is a test emergency alert from the Emergency Notifier System.",
            "https://maps.google.com/?q=12.849728,80.053077"
        );
        
        if (success) {
            return ResponseEntity.ok("✅ Test emergency email sent successfully to " + email);
        } else {
            return ResponseEntity.status(500).body("❌ Failed to send test email to " + email);
        }
    }
}
