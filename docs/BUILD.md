# MobileFingerprintUnlock — Build Guide

## 1. Prerequisites

### Windows Development Requirements
- **Operating System**: Windows 10 (1809+) or Windows 11 (21H2+) x64.
- **Compiler**: Visual Studio 2022 (MSVC v143 toolchain with C++20 support).
- **Windows SDK**: Windows 10/11 SDK (Version 10.0.22621+).
- **Build Generator**: CMake 3.22+.

### Android Development Requirements
- **Flutter SDK**: Flutter 3.x+.
- **Android SDK**: Android SDK API Level 34 (Android 14+).
- **JDK**: Java Development Kit (JDK 17+).
- **Build Tools**: Gradle 8.x.

---

## 2. Building the Windows C++ Components

### 2.1 Automated PowerShell Build Script
Run the automated build script from the root directory:

```powershell
.\scripts\Build_Windows.ps1 -BuildType Debug
```

### 2.2 Manual CMake Commands
```cmd
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --config Debug
```

Build outputs generated in `build/Debug/`:
- `MobileUnlockService.exe`: Core Windows Service.
- `UserSessionAgent.exe`: Interactive session application.
- `MobileUnlockTests.exe`: GoogleTest executable.

---

## 3. Running Unit Tests

### 3.1 Windows GoogleTest Execution
```powershell
.\scripts\Run_Tests.ps1
```

Or run directly:
```cmd
.\build\Debug\MobileUnlockTests.exe
```

### 3.2 Android Flutter Unit Tests
Navigate to the Flutter directory and run Flutter test suite:

```cmd
cd android\flutter_app
flutter test
```

---

## 4. Building the Android Application

To build the Flutter debug APK:

```cmd
cd android\flutter_app
flutter build apk --debug
```
