@echo off
SETLOCAL
SET APP_NAME=ngins
SET BUILD_DIR=dist

echo Cleaning old builds...
if exist %BUILD_DIR% rd /s /q %BUILD_DIR%
mkdir %BUILD_DIR%

echo Building for Windows (amd64, 386)...
SET GOOS=windows
SET GOARCH=amd64
go build -o %BUILD_DIR%/%APP_NAME%_windows_amd64.exe main.go
SET GOARCH=386
go build -o %BUILD_DIR%/%APP_NAME%_windows_386.exe main.go

echo Building for Linux (amd64, 386, arm, arm64)...
SET GOOS=linux
SET GOARCH=amd64
go build -o %BUILD_DIR%/%APP_NAME%_linux_amd64 main.go
SET GOARCH=386
go build -o %BUILD_DIR%/%APP_NAME%_linux_386 main.go
SET GOARCH=arm
go build -o %BUILD_DIR%/%APP_NAME%_linux_arm main.go
SET GOARCH=arm64
go build -o %BUILD_DIR%/%APP_NAME%_linux_arm64 main.go

echo Building for macOS (amd64, arm64)...
SET GOOS=darwin
SET GOARCH=amd64
go build -o %BUILD_DIR%/%APP_NAME%_darwin_amd64 main.go
SET GOARCH=arm64
go build -o %BUILD_DIR%/%APP_NAME%_darwin_arm64 main.go

echo.
echo Build complete! Binaries are located in the '%BUILD_DIR%' directory.
ENDLOCAL
