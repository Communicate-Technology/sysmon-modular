# Define the temp directory explicitly
$tempDir = "$env:TEMP"

# Function to log messages
function Log-Message {
    param (
        [string]$message,
        [string]$severity = "INFO"
    )
    Write-Output "[$severity] $message"
}

# Initialize success/error code
$successCode = 1

try {
    # Log start of script
    Log-Message "Starting script execution."

    # Download and install Wazuh agent
    Log-Message "Downloading Wazuh agent..."
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.1-1.msi -OutFile "$tempDir\wazuh-agent.msi"
    Log-Message "Installing Wazuh agent..."
    msiexec.exe /i "$tempDir\wazuh-agent.msi" /q WAZUH_MANAGER='192.9.200.190' WAZUH_REGISTRATION_SERVER='192.9.200.190'
    Log-Message "Waiting for installation to complete..."
    Start-Sleep -s 30
    Log-Message "Starting Wazuh service..."

    # Try to start the service and handle errors
    try {
        NET START WazuhSvc
    } catch {
        Log-Message "Failed to start Wazuh service: $_" -severity "ERROR"
        $successCode = 0
        throw
    }

    Log-Message "Wazuh agent installation completed successfully."

    # Download and run Sysmon installation script
    Log-Message "Downloading Sysmon installation script..."
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/Communicate-Technology/sysmon-modular/master/sysmon_install.ps1 -OutFile "$tempDir\sysmon_install.ps1"
    Log-Message "Running Sysmon installation script..."

    # Try to run the Sysmon script and handle errors
    try {
        powershell -ep Bypass "$tempDir\sysmon_install.ps1"
    } catch {
        Log-Message "Failed to run Sysmon installation script: $_" -severity "ERROR"
        $successCode = 0
        throw
    }

    Log-Message "Sysmon installation completed successfully."

    # Log successful completion
    Log-Message "Script execution completed successfully." -severity "SUCCESS"
} catch {
    # Log error
    Log-Message "An error occurred: $_" -severity "ERROR"
    $successCode = 0
    throw
} finally {
    # Output success/error code
    Write-Output "Exit code: $successCode"
}
