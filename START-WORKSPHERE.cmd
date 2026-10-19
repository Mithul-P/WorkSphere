@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Please install Node.js 24 from https://nodejs.org and run this file again.
  pause
  exit /b 1
)
if not exist node_modules (
  echo Installing WorkSphere dependencies...
  call npm.cmd install
  if errorlevel 1 (
    echo Dependency installation failed. Check your Internet connection and try again.
    pause
    exit /b 1
  )
)
echo Open http://localhost:3000 after the server is ready.
call npm.cmd run dev
pause
