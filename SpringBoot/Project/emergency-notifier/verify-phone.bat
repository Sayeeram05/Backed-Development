@echo off
echo ================================
echo   TWILIO PHONE VERIFICATION
echo ================================
echo.
echo Your SMS is failing because your phone number needs to be verified in Twilio.
echo.
echo Follow these steps:
echo.
echo 1. Open your web browser
echo 2. Go to: https://console.twilio.com/
echo 3. Sign in with your Twilio account
echo 4. Navigate to: Phone Numbers ^> Verified Caller IDs
echo 5. Click "Add a new caller ID"
echo 6. Enter your phone number: +917418022289
echo 7. Twilio will call or SMS you with a verification code
echo 8. Enter the verification code to complete verification
echo.
echo After verification, restart your application and test again!
echo.
echo ================================
echo   Technical Details
echo ================================
echo Error Code: 30044
echo Meaning: Message blocked - destination number blocked
echo Cause: Trial account can only send to verified numbers
echo Solution: Verify your phone number in Twilio Console
echo.
pause