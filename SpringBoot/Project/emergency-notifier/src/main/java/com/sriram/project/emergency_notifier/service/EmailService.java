package com.sriram.project.emergency_notifier.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {
    
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
    
    @Autowired
    private JavaMailSender javaMailSender;
    
    @Value("${spring.mail.username}")
    private String fromEmail;
    
    public boolean sendEmail(String toEmail, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject(subject);
            message.setText(body);
            
            javaMailSender.send(message);
            logger.info("Email sent successfully to: {}", toEmail);
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to send email to {}: {}", toEmail, e.getMessage());
            return false;
        }
    }
    
    public boolean sendEmergencyAlert(String toEmail, String senderName, String senderEmail, 
                                    String alertMessage, String location) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("🚨 URGENT: Emergency Alert from " + senderName);
            
            String htmlBody = createEmergencyEmailTemplate(senderName, senderEmail, alertMessage, location);
            helper.setText(htmlBody, true);
            
            javaMailSender.send(mimeMessage);
            logger.info("Emergency alert email sent successfully to: {}", toEmail);
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to send emergency alert to {}: {}", toEmail, e.getMessage());
            return false;
        }
    }
    
    private String createEmergencyEmailTemplate(String senderName, String senderEmail, 
                                              String alertMessage, String location) {
        return """
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                    .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                    .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
                    .content { padding: 30px; }
                    .alert-box { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
                    .info-section { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
                    .location-link { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0; }
                    .footer { background-color: #6c757d; color: white; padding: 15px; text-align: center; font-size: 12px; }
                    .urgent { color: #dc3545; font-weight: bold; font-size: 18px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚨 EMERGENCY ALERT</h1>
                        <p class="urgent">IMMEDIATE ATTENTION REQUIRED</p>
                    </div>
                    <div class="content">
                        <div class="alert-box">
                            <h2>Emergency Situation Reported</h2>
                            <p><strong>%s</strong> has sent an emergency alert and may need immediate assistance.</p>
                        </div>
                        
                        <div class="info-section">
                            <h3>📧 Contact Information</h3>
                            <p><strong>Name:</strong> %s</p>
                            <p><strong>Email:</strong> %s</p>
                        </div>
                        
                        <div class="info-section">
                            <h3>💬 Alert Message</h3>
                            <p style="font-size: 16px; color: #333;">%s</p>
                        </div>
                        
                        <div class="info-section">
                            <h3>📍 Location</h3>
                            <p>Click the link below to view the location:</p>
                            <a href="%s" class="location-link" target="_blank">🗺️ View Location on Maps</a>
                        </div>
                        
                        <div class="alert-box">
                            <p><strong>⏰ Time Sent:</strong> %s</p>
                            <p><strong>What to do:</strong></p>
                            <ul>
                                <li>Contact %s immediately</li>
                                <li>Check their location using the map link</li>
                                <li>Call emergency services if needed</li>
                                <li>Respond to this alert as soon as possible</li>
                            </ul>
                        </div>
                    </div>
                    <div class="footer">
                        <p>This is an automated emergency alert from Emergency Notifier System</p>
                        <p>Do not reply to this email. Contact the sender directly for assistance.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(
                senderName, senderName, senderEmail, alertMessage, location,
                java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                senderName
            );
    }
}