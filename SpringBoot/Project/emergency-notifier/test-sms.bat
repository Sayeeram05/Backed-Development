@echo off
echo Starting Spring Boot application in background...
start /B .\mvnw.cmd spring-boot:run > app.log 2>&1

echo Waiting for application to start...
timeout /t 30 /nobreak > nul

echo Testing SMS...
curl "http://localhost:8080/test-sms" > sms-test-result.txt 2>&1

echo Test completed. Check sms-test-result.txt for results.