# 🚨 Emergency Contact Notifier - Demo Guide

## ✅ Application Status

✅ **Backend**: Spring Boot application running on http://localhost:8080  
✅ **Frontend**: Responsive web interface available  
✅ **Database**: H2 in-memory database configured  
✅ **APIs**: RESTful endpoints ready for testing

## 🎯 Quick Demo Steps

### 1. Access the Application

- Open your browser and go to: **http://localhost:8080**
- You should see the Emergency Contact Notifier web interface

### 2. Register a User

1. Click the **"Register"** tab (should be active by default)
2. Fill in the user details:

   - **Name**: John Doe
   - **Email**: john.doe@example.com
   - **Phone**: +1234567890
   - **Password**: password123

3. Add emergency contacts:
   - **Contact 1**:
     - Name: Emergency Contact 1
     - Phone: +0987654321
     - Email: emergency1@example.com
4. Click **"Add Another Contact"** if you want to add more contacts
5. Click **"Register"** to save the user

### 3. Send Emergency Alert

1. Click the **"Send Alert"** tab
2. Enter the registered email: **john.doe@example.com**
3. Add a custom message (optional): "I'm in danger! Please help!"
4. Check **"Include my current location"** if you want to share GPS coordinates
5. Click **"🚨 Send Emergency Alert"**

### 4. View Results

- The system will display user information and contacts
- Success/error messages will appear at the bottom
- Check console logs for detailed processing information

## 🔧 API Testing with curl/Postman

### Test Status Endpoint

```bash
GET http://localhost:8080/status
```

### Register User

```bash
POST http://localhost:8080/register
Content-Type: application/json

{
  "name": "Jane Smith",
  "email": "jane.smith@example.com",
  "phone": "+1111111111",
  "password": "password456",
  "contacts": [
    {
      "contactName": "Family Member",
      "contactPhone": "+2222222222",
      "contactEmail": "family@example.com"
    },
    {
      "contactName": "Close Friend",
      "contactPhone": "+3333333333",
      "contactEmail": "friend@example.com"
    }
  ]
}
```

### Send Alert

```bash
POST http://localhost:8080/alert
Content-Type: application/json

{
  "userEmail": "jane.smith@example.com",
  "customMessage": "Emergency! Need immediate help!",
  "latitude": 40.7128,
  "longitude": -74.0060
}
```

### Get User Contacts

```bash
GET http://localhost:8080/user/jane.smith@example.com/contacts
```

### Get User Info

```bash
GET http://localhost:8080/user/jane.smith@example.com
```

## 🗄️ Database Access (H2 Console)

1. Go to: **http://localhost:8080/h2-console**
2. Use these settings:
   - **JDBC URL**: `jdbc:h2:mem:emergency_notifier`
   - **User Name**: `sa`
   - **Password**: (leave empty)
3. Click "Connect"
4. You can then view the `USERS` and `CONTACTS` tables

### Sample SQL Queries

```sql
-- View all users
SELECT * FROM USERS;

-- View all contacts
SELECT * FROM CONTACTS;

-- View users with their contacts
SELECT u.name, u.email, c.contact_name, c.contact_phone, c.contact_email
FROM USERS u
LEFT JOIN CONTACTS c ON u.id = c.user_id;
```

## ⚠️ Important Notes

### Current Configuration (Demo Mode)

- **Database**: H2 in-memory (data resets on restart)
- **Email**: Demo configuration (emails won't actually send)
- **SMS**: Demo configuration (SMS won't actually send)

### For Production Use

1. **Database**: Switch to MySQL/PostgreSQL in `application.properties`
2. **Email**: Configure with real Gmail/SMTP credentials
3. **SMS**: Set up actual Twilio account credentials
4. **Security**: Implement proper password hashing and authentication

## 🎨 Frontend Features Demonstrated

✅ **Responsive Design**: Works on desktop and mobile  
✅ **Form Validation**: Real-time validation for inputs  
✅ **Dynamic Contacts**: Add/remove multiple emergency contacts  
✅ **Location Services**: GPS location integration  
✅ **AJAX Calls**: Seamless API communication  
✅ **User Feedback**: Success/error message display  
✅ **Modern UI**: Clean, professional interface

## 🚀 Sample Alert Message Format

When an alert is sent, it creates a message like this:

```
🚨 EMERGENCY ALERT!

From: John Doe
Phone: +1234567890
Email: john.doe@example.com

Message: I'm in danger! Please help!

Location: https://maps.google.com/?q=40.7128,-74.0060

This is an automated emergency alert. Please respond immediately!
```

## 🔍 Troubleshooting

### Common Issues:

1. **Can't access http://localhost:8080**

   - Check if application is running in terminal
   - Look for "Tomcat started on port 8080" message

2. **Registration fails**

   - Check console for validation errors
   - Ensure all required fields are filled

3. **Alert fails**

   - Verify user exists with the provided email
   - Check if user has emergency contacts

4. **Database issues**
   - Restart application to reset H2 database
   - Check H2 console for data verification

### Success Indicators:

- ✅ Green success messages
- ✅ User info displays after alert
- ✅ No console errors
- ✅ Data visible in H2 console

---

**🎉 Congratulations!** You now have a fully functional Emergency Contact Notifier system running locally. The application demonstrates modern full-stack development with Spring Boot, JPA, responsive web design, and RESTful APIs.
