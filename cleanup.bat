@echo off
echo ========================================
echo  Nettoyage fichiers obsolètes ClariDoc
echo ========================================

cd /d D:\CSharp_CarmeraDll\Web_Backend

echo.
echo [1/2] Suppression fichiers inspect_notch...
del /f inspect_notch.py
del /f inspect_notch_v2.py
del /f inspect_notch_v3.py
del /f inspect_notch_v4.py
del /f inspect_notch_v5.py
del /f test_notch_auth.py
del /f test_notch_auth_v2.py

echo.
echo [2/2] Suppression fichiers de debug NotchPay...
del /f payments\migrations\0001_initial.py 2>nul

echo.
echo ✅ Nettoyage terminé !
echo.
echo Prochaine étape : corriger l'alias dans claridoc_api/urls.py
pause
