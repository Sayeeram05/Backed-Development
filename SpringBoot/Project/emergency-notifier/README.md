# Emergency Contact Notifier

A comprehensive web application that allows users to register emergency contacts and send instant alerts (SMS and Email) to them with one click during emergencies.

## 🚨 Features

- **User Registration**: Register with personal details and emergency contacts
- **Instant Alerts**: Send emergency alerts via SMS and Email with one click
- **Location Sharing**: Include GPS location in emergency messages
- **Responsive UI**: Modern, mobile-friendly interface
- **Real-time Validation**: Client-side form validation
- **RESTful API**: Well-structured backend APIs

## 🛠️ Tech Stack

### Backend

- **Spring Boot 3.5.7** (Java 17)
- **Spring Data JPA** for database operations
- **MySQL** for data persistence
- **Twilio API** for SMS notifications
- **JavaMailSender** for email notifications
- **Spring Validation** for input validation

### Frontend

- **HTML5, CSS3, JavaScript**
- **Responsive Design**
- **Modern UI/UX**

## 📋 Prerequisites

1. **Java 17 or higher**
2. **Maven 3.6+**
3. **MySQL 8.0+**
4. **Twilio Account** (for SMS functionality)
5. **Email Account** (Gmail recommended for SMTP)

## 🚀 Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd emergency-notifier
```

### 2. Database Setup

1. Install MySQL and create a database:
   ```sql
   CREATE DATABASE emergency_notifier;
   ```
2. Run the schema script:
   ```bash
   mysql -u root -p emergency_notifier < database/schema.sql
   ```

### 3. Configure Application Properties

Update `src/main/resources/application.properties`:

```properties
# Database configuration
spring.datasource.url=jdbc:mysql://localhost:3306/emergency_notifier?createDatabaseIfNotExist=true&useSSL=false&serverTimezone=UTC
spring.datasource.username=your_mysql_username
spring.datasource.password=your_mysql_password

# Email configuration (Gmail example)
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password

# Twilio configuration
twilio.account.sid=your-twilio-account-sid
twilio.auth.token=your-twilio-auth-token
twilio.phone.number=your-twilio-phone-number
```

### 4. Twilio Setup

1. Create a Twilio account at [https://www.twilio.com](https://www.twilio.com)
2. Get your Account SID and Auth Token from the Twilio Console
3. Purchase a phone number for sending SMS
4. Update the Twilio configuration in `application.properties`

### 5. Email Setup (Gmail)

1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate a password for "Mail"
3. Use this app password in `application.properties`

### 6. Build and Run

```bash
# Build the application
./mvnw clean package

# Run the application
./mvnw spring-boot:run
```

The application will start on `http://localhost:8080`

## 📱 How to Use

### Registration

1. Open `http://localhost:8080` in your browser
2. Click "Register" tab
3. Fill in your personal details
4. Add emergency contacts (at least one required)
5. Click "Register"

### Sending Alerts

1. Click "Send Alert" tab
2. Enter your registered email
3. Add a custom message (optional)
4. Check "Include location" to share GPS coordinates
5. Click "🚨 Send Emergency Alert"

## 🔗 API Endpoints

### User Registration

```http
POST /register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "password": "password123",
  "contacts": [
    {
      "contactName": "Emergency Contact",
      "contactPhone": "+0987654321",
      "contactEmail": "contact@example.com"
    }
  ]
}
```

### Send Alert

```http
POST /alert
Content-Type: application/json

{
  "userEmail": "john@example.com",
  "customMessage": "I'm in danger!",
  "latitude": 12.9716,
  "longitude": 77.5946
}
```

### Get User Contacts

```http
GET /user/{email}/contacts
```

### Get User Info

```http
GET /user/{email}
```

### Health Check

```http
GET /status
```

## 📁 Project Structure

```
emergency-notifier/
├── src/
│   ├── main/
│   │   ├── java/com/sriram/project/emergency_notifier/
│   │   │   ├── config/           # Configuration classes
│   │   │   ├── dto/              # Data Transfer Objects
│   │   │   ├── entity/           # JPA Entities
│   │   │   ├── repository/       # Data repositories
│   │   │   ├── service/          # Business logic
│   │   │   ├── EmergencyNotifierController.java
│   │   │   └── EmergencyNotifierApplication.java
│   │   └── resources/
│   │       ├── static/           # Frontend files
│   │       │   ├── css/
│   │       │   ├── js/
│   │       │   └── index.html
│   │       └── application.properties
│   └── test/                     # Test files
├── database/
│   └── schema.sql               # Database schema
├── pom.xml                      # Maven dependencies
└── README.md
```

## 🚨 Sample Alert Message

```
🚨 EMERGENCY ALERT!

From: John Doe
Phone: +1234567890
Email: john@example.com

Message: I'm in danger! Please reach me immediately.

Location: https://maps.google.com/?q=12.9716,77.5946

This is an automated emergency alert. Please respond immediately!
```

## 🔧 Troubleshooting

### Common Issues

1. **Port 8080 already in use**

   ```bash
   # Kill process using port 8080
   netstat -ano | findstr :8080
   taskkill /PID <PID> /F
   ```

2. **Database connection failed**

   - Ensure MySQL is running
   - Check database credentials in `application.properties`
   - Verify database exists

3. **SMS not sending**

   - Verify Twilio credentials
   - Check phone number format (+countrycode)
   - Ensure sufficient Twilio balance

4. **Email not sending**
   - Check Gmail app password
   - Verify SMTP settings
   - Enable "Less secure app access" if needed

## 🔒 Security Notes

- **Password Hashing**: In production, implement proper password hashing (BCrypt)
- **Input Validation**: Server-side validation is implemented
- **CORS**: Configure properly for production
- **HTTPS**: Use HTTPS in production
- **API Keys**: Never commit API keys to version control

## 🚀 Production Deployment

1. **Environment Variables**: Use environment variables for sensitive data
2. **Database**: Use production-grade database with proper backups
3. **Monitoring**: Add logging and monitoring
4. **Load Balancing**: Use reverse proxy for multiple instances
5. **SSL Certificate**: Implement HTTPS

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support and questions:

- Email: support@emergency-notifier.com
- GitHub Issues: [Create an issue](https://github.com/your-repo/emergency-notifier/issues)

---

**⚠️ Important**: This application is designed for emergency situations. Test thoroughly before relying on it for actual emergencies. Always have backup communication methods available.
