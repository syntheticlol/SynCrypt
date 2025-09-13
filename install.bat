@echo off
REM SynCrypt Windows Installer

REM Check for gcc
where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo GCC not found. Please install MinGW or a compatible GCC and add it to your PATH.
    exit /b 1
)

REM Build SynCrypt
if exist syncrypt_tool.c (
    gcc -o syncrypt.exe syncrypt_tool.c syncrypt.c
    if %errorlevel% neq 0 (
        echo Build failed.
        exit /b 1
    )
    echo Build successful: syncrypt.exe created.
) else (
    echo syncrypt_tool.c not found in this directory.
    exit /b 1
)

pause
