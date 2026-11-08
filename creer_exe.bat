@echo off
title Scanova - Creation du programme
cd /d "%~dp0"

set PY=
where py >nul 2>nul && set PY=py -3
if defined PY goto python_ok
where python >nul 2>nul && set PY=python
if defined PY goto python_ok

echo Python est introuvable sur cet ordinateur.
echo Installez-le depuis https://www.python.org/downloads/
echo Cochez bien "Add Python to PATH" pendant l'installation, puis relancez ce fichier.
start https://www.python.org/downloads/
pause
exit /b 1

:python_ok
echo.
echo [1/2] Installation des dependances...
%PY% -m pip install --upgrade pip
%PY% -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto erreur

echo.
echo [2/2] Creation de Scanova.exe, cela peut prendre quelques minutes...
del /q "Scanova.exe" 2>nul
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name Scanova --icon "%~dp0icone.ico" --add-data "%~dp0icone.ico;." --collect-all customtkinter --collect-all zeroconf --hidden-import win32com.client --hidden-import pythoncom --hidden-import pywintypes scanova.py
if errorlevel 1 goto erreur


echo Actualisation des icones Windows...
ie4uinit.exe -show >nul 2>nul
ie4uinit.exe -ClearIconCache >nul 2>nul

echo.
echo Termine ! Le programme est ici : %~dp0Scanova.exe
echo Vous pouvez le copier ou vous voulez, il fonctionne tout seul.
pause
exit /b 0

:erreur
echo.
echo Une erreur est survenue. Verifiez votre connexion internet et relancez.
pause
exit /b 1
