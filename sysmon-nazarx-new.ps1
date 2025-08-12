$tempDir = "$env:TEMP"

function Log-Message { param ( [string]$message, [string]$severity = "INFO" ) Write-Output "[$severity] $message" }

$successCode = 0

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

try { Log-Message "Starting script execution."

    Log-Message "Checking if Wazuh service is already running..."
    $wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhService -and $wazuhService.Status -eq 'Running') {
        Log-Message "Wazuh service is already running. Skipping installation."
    } else {
        Log-Message "Downloading Wazuh agent..."
        Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi -OutFile "$tempDir\wazuh-agent.msi"
        Log-Message "Installing Wazuh agent..."
        msiexec.exe /i "$tempDir\wazuh-agent.msi" /q WAZUH_MANAGER='192.9.200.190' WAZUH_REGISTRATION_SERVER='192.9.200.190'
        Log-Message "Waiting for installation to complete..."
        Start-Sleep -s 30
        Log-Message "Starting Wazuh service..."

        try {
            NET START WazuhSvc
        } catch {
            Log-Message "Failed to start Wazuh service: $_" -severity "ERROR"
            throw
        }
    }

    Log-Message "Wazuh agent installation completed successfully."

    Log-Message "Checking if Sysmon service is already running..."
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    if ($sysmonService -and $sysmonService.Status -eq 'Running') {
        Log-Message "Sysmon service is already running. Skipping installation."
    } else {
        Log-Message "Checking if Sysinternals folder exists..."
        if (Test-Path -Path "$env:ProgramFiles\Sysinternals") {
            Log-Message "Sysinternals folder already exists. Skipping installation."
        } else {
            Log-Message "Downloading Sysmon installation script..."
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/Communicate-Technology/sysmon-modular/master/sysmon_install.ps1 -OutFile "$tempDir\sysmon_install.ps1"
            Log-Message "Running Sysmon installation script..."

            try {
                powershell -ep Bypass "$tempDir\sysmon_install.ps1"
            } catch {
                Log-Message "Failed to run Sysmon installation script: $_" -severity "ERROR"
                throw
            }
        }
    }

    Log-Message "Sysmon installation completed successfully."

    Log-Message "Script execution completed successfully." -severity "SUCCESS"
    $successCode = 0
} catch { Log-Message "An error occurred: $_" -severity "ERROR" throw } finally { Write-Output "Exit code: $successCode" }
