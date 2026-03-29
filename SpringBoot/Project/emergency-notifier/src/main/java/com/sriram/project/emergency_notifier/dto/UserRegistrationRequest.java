package com.sriram.project.emergency_notifier.dto;

import java.util.List;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UserRegistrationRequest {
    
    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    private String name;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Please provide a valid email")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
    
    private List<ContactRequest> contacts;
    
    // Constructors
    public UserRegistrationRequest() {}
    
    public UserRegistrationRequest(String name, String email, String password, List<ContactRequest> contacts) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.contacts = contacts;
    }
    
    // Getters and Setters
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public List<ContactRequest> getContacts() {
        return contacts;
    }
    
    public void setContacts(List<ContactRequest> contacts) {
        this.contacts = contacts;
    }
}