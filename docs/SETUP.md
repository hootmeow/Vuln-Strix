# Vuln-Strix Windows Setup Guide

This guide will walk you through setting up Vuln-Strix on a Windows PC for testing, including the email ingestion feature.

## 1. Install Prerequisites

### Step A: Install Go (Golang)
1.  Download the installer: [https://go.dev/dl/](https://go.dev/dl/) (Select the Microsoft Windows MSI).
2.  Run the installer and follow the prompts.
3.  Open a **new** PowerShell or Command Prompt window.
4.  Verify installation by running:
    ```powershell
    go version
    ```
    *You should see something like `go version go1.22.x windows/amd64`.*

### Step B: Install TDM-GCC (Required for SQLite)
Since we are using SQLite, we need a C compiler.
1.  Download TDM-GCC: [https://jmeubank.github.io/tdm-gcc/](https://jmeubank.github.io/tdm-gcc/) (Click "tdm64-gcc-10.3.0-2.exe" or similar).
2.  Run the installer. **Important:** Ensure the "Add to Path" option is checked (it usually is by default).
3.  Click "Create".
4.  Open a **new** terminal (close the old one) to ensure the path updates.
5.  Verify by running:
    ```powershell
    gcc --version
    ```

## 2. Prepare the Project

1.  Open your terminal (PowerShell) and navigate to the project directory:
    ```powershell
    cd c:\Users\david.saunders\Documents\GitHub\Vuln-Strix\Vuln-Strix
    ```
2.  Download project dependencies:
    ```powershell
    go mod tidy
    ```
    *This will download all the libraries we added (like `go-imap`, `gorm`, etc.).*

## 3. Configuration (Email)

1.  Locate the file `config.example.yaml` in the project folder.
2.  Copy it and rename the copy to `config.yaml`.
3.  Open `config.yaml` in Notepad or VS Code.
4.  Edit the settings (Example for Gmail):
    ```yaml
    server:
      port: 8080

    email:
      enabled: true
      imap_server: "imap.gmail.com"
      imap_port: 993
      username: "your-email@gmail.com"
      password: "your-app-password"  # NOTE: Do not use your login password. Generate an App Password in Google Account settings.
      poll_interval_seconds: 60
    ```

## 4. Build the Application

Run the build command:
```powershell
go build -o vuln-strix.exe ./cmd/vuln-strix
```
*If this completes without output, it was successful. You will see `vuln-strix.exe` in the folder.*

## 5. Running & Testing

### Option A: Run Manually (Best for Testing)
Run the server mode. It will also start the email poller in the background.
```powershell
./vuln-strix.exe server
```
- You should see logs indicating the server started and "Checking for new emails...".
- Send an email with a `.nessus` file attachment to the configured email address.
- Wait (up to 60 seconds as per config), and watch the terminal logs for "Downloaded attachment...".

### Option B: Install as a Windows Service
To run it permanently looking for emails:
1.  Open PowerShell as **Administrator**.
2.  Run:
    ```powershell
    ./vuln-strix.exe install
    ./vuln-strix.exe start
    ```
3.  To stop/remove:
    ```powershell
    ./vuln-strix.exe stop
    ./vuln-strix.exe remove
    ```
