# Emergency Notifier Setup Guide

## 🚀 Application Status

✅ **MySQL Database**: Successfully connected to `emergency_notifier` database  
✅ **User Registration**: Working perfectly  
✅ **Data Persistence**: All operations successful  
✅ **JSON Serialization**: Fixed circular reference issue

## 📧 Email Configuration

To enable email notifications, update your `application.properties`:

```properties
# Gmail SMTP Configuration
spring.mail.username=your.email@gmail.com
spring.mail.password=your-16-digit-app-password
```

### How to get Gmail App Password:

1. Go to your Google Account settings
2. Security → 2-Step Verification (must be enabled)
3. App passwords → Generate new app password
4. Use the 16-digit password (not your regular Gmail password)

## 📱 SMS Configuration (Twilio)

To enable SMS notifications, update your `application.properties`:

```properties
# Twilio Configuration
twilio.account.sid=your-twilio-account-sid
twilio.auth.token=your-twilio-auth-token
twilio.phone.number=+1234567890
```

### How to get Twilio credentials:

1. Sign up at [twilio.com](https://twilio.com)
2. Get a free trial account
3. Copy Account SID and Auth Token from your dashboard
4. Purchase or get a trial phone number

## 🗄️ Database Setup

Your MySQL database `emergency_notifier` is ready with:

- `users` table (id, name, email, phone, password)
- `contacts` table (id, contact_name, contact_phone, contact_email, user_id)

## 🌐 API Endpoints

- **POST** `/api/register` - Register new user with contacts
- **POST** `/api/alert` - Send emergency alert
- **GET** `/api/user/{email}` - Get user information
- **GET** `/api/user/{email}/contacts` - Get user's contacts
- **GET** `/api/status` - Health check

## 🔧 Next Steps

1. **Update Email Credentials**: Replace placeholder email settings
2. **Update Twilio Credentials**: Replace placeholder SMS settings
3. **Test Registration**: Use the web interface at http://localhost:8080
4. **Test Alerts**: Try sending emergency notifications

## 🎯 Current Issues Fixed

- ✅ MySQL connection and database operations
- ✅ User registration and data persistence
- ✅ JSON circular reference (User ↔ Contact relationship)
- ⚠️ Email authentication (needs real Gmail credentials)
- ⚠️ SMS authentication (needs real Twilio credentials)

The application is now fully functional with MySQL!
