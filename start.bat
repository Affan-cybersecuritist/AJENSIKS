@echo off
echo ========================================================
echo   Starting DevSecOps AI Swarm Platform (Backend + Frontend)
echo ========================================================
echo.
echo Backend  (AI Swarm Engine): http://127.0.0.1:8000
echo Frontend (Login/Dashboard): http://localhost:3000
echo.

call npm run dev:all

pause
