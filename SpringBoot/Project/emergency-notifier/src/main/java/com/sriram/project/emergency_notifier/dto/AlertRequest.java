package com.sriram.project.emergency_notifier.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AlertRequest {
    
    @NotBlank(message = "User email is required")
    @Email(message = "Please provide a valid email")
    private String userEmail;
    
    private String customMessage;
    
    private Double latitude;
    
    private Double longitude;
    
    // Constructors
    public AlertRequest() {}
    
    public AlertRequest(String userEmail, String customMessage, Double latitude, Double longitude) {
        this.userEmail = userEmail;
        this.customMessage = customMessage;
        this.latitude = latitude;
        this.longitude = longitude;
    }
    
    // Getters and Setters
    public String getUserEmail() {
        return userEmail;
    }
    
    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }
    
    public String getCustomMessage() {
        return customMessage;
    }
    
    public void setCustomMessage(String customMessage) {
        this.customMessage = customMessage;
    }
    
    public Double getLatitude() {
        return latitude;
    }
    
    public void setLatitude(Double latitude) {
        this.latitude = latitude;
    }
    
    public Double getLongitude() {
        return longitude;
    }
    
    public void setLongitude(Double longitude) {
        this.longitude = longitude;
    }
}