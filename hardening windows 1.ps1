#Copy supporting data
    #Copy file audit.csv to the specified folders
    Write-Host "Copying audit.csv to the specified folders..." -ForegroundColor Yellow 

    # Define the paths
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $remediasiPath = Join-Path -Path $desktopPath -ChildPath "remediasi"
    $newAuditCsvPath = Join-Path -Path $remediasiPath -ChildPath "audit.csv"

    # Check and rename existing audit.csv, if it exists
    if (Test-Path "C:\Windows\security\audit\audit.csv") {
        Rename-Item -Path "C:\Windows\security\audit\audit.csv" -NewName "audit.csv.bak"
    } else {
        Copy-Item -Path $newAuditCsvPath -Destination "C:\Windows\security\audit\audit.csv"
    }

    if (Test-Path "C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv") {
        Rename-Item -Path "C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv" -NewName "audit.csv.bak"
    } else {
        Copy-Item -Path $newAuditCsvPath -Destination "C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv"
    }

    # Copy the new audit.csv from the 'remediasi' folder on the desktop to the specified folders
    Copy-Item -Path $newAuditCsvPath -Destination "C:\Windows\security\audit\audit.csv"
    Copy-Item -Path $newAuditCsvPath -Destination "C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv"

    Write-Host "audit.csv copied successfully." -ForegroundColor Green
    Write-Host "Do a reset first so that the audit runs" -ForegroundColor Yellow
Start-Sleep -Seconds 2

    #Copy Template AdmPwd,MSS-legacy,SecGuide
    Write-Host "Copying Template AdmPwd,MSS-legacy,SecGuide..." -ForegroundColor Yellow 

    # Copy the new AdmPwd.admx and AdmPwd.adml to the specified folders
    $admPwdAdmxPath = Join-Path -Path $remediasiPath -ChildPath "AdmPwd.admx"
    $admPwdAdmlPath = Join-Path -Path $remediasiPath -ChildPath "AdmPwd.adml"

    Copy-Item -Path $admPwdAdmxPath -Destination "C:\Windows\PolicyDefinitions\AdmPwd.admx"
    Copy-Item -Path $admPwdAdmlPath -Destination "C:\Windows\PolicyDefinitions\en-US\AdmPwd.adml"

    # Copy the new MSS-legacy.admx and MSS-legacy.adml to the specified folders
    $mssLegacyAdmxPath = Join-Path -Path $remediasiPath -ChildPath "MSS-legacy.admx"
    $mssLegacyAdmlPath = Join-Path -Path $remediasiPath -ChildPath "MSS-legacy.adml"

    Copy-Item -Path $mssLegacyAdmxPath -Destination "C:\Windows\PolicyDefinitions\MSS-legacy.admx"
    Copy-Item -Path $mssLegacyAdmlPath -Destination "C:\Windows\PolicyDefinitions\en-US\MSS-legacy.adml"

    # Copy the new SecGuide.admx and SecGuide.adml to the specified folders
    $secGuideAdmxPath = Join-Path -Path $remediasiPath -ChildPath "SecGuide.admx"
    $secGuideAdmlPath = Join-Path -Path $remediasiPath -ChildPath "SecGuide.adml"

    Copy-Item -Path $secGuideAdmxPath -Destination "C:\Windows\PolicyDefinitions\SecGuide.admx"
    Copy-Item -Path $secGuideAdmlPath -Destination "C:\Windows\PolicyDefinitions\en-US\SecGuide.adml"

    Write-Host "Templates copied successfully." -ForegroundColor Green
Start-Sleep -Seconds 2

#Configure 'Accounts: Rename administrator account'.
    Write-Host "Configure 'Accounts: Rename Administrator account'."
    # Define the new username for the Administrator account
    $oldName = "Administrator"
    # Prompt the user for a new username
    $newName = Read-Host -Prompt "Enter a new username for the Administrator account:"

    # Check if the user exists and rename if found
    if (Get-LocalUser -Name $oldName -ErrorAction SilentlyContinue) {
        # Attempt to rename the user account
        try {
            Rename-LocalUser -Name $oldName -NewName $newName -ErrorAction Stop
            Write-Host "User '$oldName' successfully changed to '$newName'." -ForegroundColor Green
        } catch {
            Write-Host "Failed to change username: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "User by name '$oldName' not found." -ForegroundColor Red
    }

Start-Sleep -Seconds 2 

#Configure 'Accounts: Rename Guest account'.
    Write-Host "Configure 'Accounts: Rename Guest account'."
    # Define the new username for the Guest account
    $oldName = "Guest"
    # Prompt the user for a new username
    $newName = Read-Host -Prompt "Enter a new username for the Guest account:"

    # Check if the user exists and rename if found
    if (Get-LocalUser -Name $oldName -ErrorAction SilentlyContinue) {
        # Attempt to rename the user account
        try {
            Rename-LocalUser -Name $oldName -NewName $newName -ErrorAction Stop
            Write-Host "User '$oldName' successfully changed to '$newName'." -ForegroundColor Green
        } catch {
            Write-Host "Failed to change username: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "User by name '$oldName' not found." -ForegroundColor Red
    }

Start-Sleep -Seconds 2 

#Set enforce password history to 24
Write-Host "Set enforce password history to 24"
    net accounts /uniquepw:24
Start-Sleep -Seconds 2 

#Set minimum password age to 1 day
Write-Host "Set minimum password age to 1 day"
    net accounts /minpwage:1
Start-Sleep -Seconds 2 

#Set minimum password length to 14 characters
Write-Host "Set minimum password length to 14 characters"
    net accounts /minpwlen:14
Start-Sleep -Seconds 2 

#Set account lockout threshold to 5 invalid login attempts
Write-Host "Set account lockout threshold to 5 invalid login attempts"
    net accounts /lockoutthreshold:5
Start-Sleep -Seconds 2 

#Display the current password policy settings
Write-Host "Display the current password policy settings"
    net accounts
Start-Sleep -Seconds 2 

#Ensure Relax minimum password length limits is set to Enabled
Write-Host "Ensure Relax minimum password length limits is set to Enabled"
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SAM' -Name 'RelaxMinimumPasswordLengthLimits' -Value 1 -Type DWord
Start-Sleep -Seconds 2 

#Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts
Write-Host "Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Value 3 -Type DWord
Start-Sleep -Seconds 2 

#Ensure Interactive logon: Dont display last signed-in is set to Enabled
Write-Host "Ensure Interactive logon: Dont display last signed-in is set to Enabled"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'dontdisplaylastusername' -Value 1
Start-Sleep -Seconds 2 

#Ensure Interactive logon: Machine inactivity limit is set to 900 or fewer second(s), but not 0
Write-Host "Ensure Interactive logon: Machine inactivity limit is set to 900 or fewer second(s), but not 0"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord
Start-Sleep -Seconds 2 

#Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher
Write-Host "Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher"
    Set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'scremoveoption' -Value 2 
Start-Sleep -Seconds 2 

#Ensure Network security: Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types
Write-Host "Ensure Network security: Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types"
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $registryName = "SupportedEncryptionTypes"
    $registryValue = 2147483640

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2 

#Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled
Write-Host "Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled"
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord
Start-Sleep -Seconds 2 

#Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop
Write-Host "Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop"
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
Start-Sleep -Seconds 2 

#Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests
Write-Host "Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests"
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0
Start-Sleep -Seconds 2 

#Ensure Include command line in process creation events is set to Enabled
Write-Host "Ensure Include command line in process creation events is set to Enabled"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
Start-Sleep -Seconds 2 

#Ensure Encryption Oracle Remediation is set to Enabled: Force Updated Clients 
Write-Host "Ensure Encryption Oracle Remediation is set to Enabled: Force Updated Clients"
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
    $registryName = "AllowEncryptionOracle"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2 

#Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'.
Write-Host "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "SCENoApplyLegacyAuditPolicy"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only).
Write-Host "Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $registryName = "LdapEnforceChannelBinding"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only).
Write-Host "Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $registryName = "LDAPServerIntegrity"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Configure 'Interactive logon: Message text for users attempting to log on'.
Write-Host "Configure 'Interactive logon: Message text for users attempting to log on'."
    # Define the message text
    $messageText = "This system is for authorized users only. Unauthorized access is prohibited."

    # Set the message text
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -Value $messageText
    Start-Sleep -Seconds 2

#Configure 'Interactive logon: Message title for users attempting to log on'.
Write-Host "Configure 'Interactive logon: Message title for users attempting to log on'."
    # Define the message title
    $messageTitle = "Warning"

    # Set the message title
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Value $messageTitle
    Start-Sleep -Seconds 2

#Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only).
Write-Host "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryName = "CachedLogonsCount"
    $registryValue = 3

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only).
Write-Host "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryName = "ForceUnlockLogon"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'.
Write-Host "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $registryName = "RequireSecuritySignature"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'.
Write-Host "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $registryName = "RequireSecuritySignature"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'.
Write-Host "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $registryName = "EnableSecuritySignature"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only).
Write-Host "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $registryName = "SMBServerNameHardeningLevel"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only).
Write-Host "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "restrictanonymous"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'.
Write-Host "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "disabledomaincreds"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only).
Write-Host "Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $registryName = "NullSessionPipes"
    $registryValue = "netlogon,samr,lsarpc"

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only).
Write-Host "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "RestrictRemoteSAM"
    $registryValue = "O:BAG:BAD:(A;;RC;;;BA)"

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'.
Write-Host "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "UseMachineId"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
Write-Host "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "LmCompatibilityLevel"
    $registryValue = 5

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
Write-Host "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryName = "NTLMMinServerSec"
    $registryValue = 537395200

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.
Write-Host "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $registryName = "NTLMMinClientSec"
    $registryValue = 536870912

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'.
Write-Host "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryName = "ConsentPromptBehaviorAdmin"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'.
Write-Host "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryName = "ConsentPromptBehaviorUser"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only).
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"
    $registryName = "Start"
    $registryValue = 4

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'.
Write-Host "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $registryName = "EnableFirewall"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'.
Write-Host "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $registryName = "DefaultInboundAction"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'.
Write-Host "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $registryName = "DefaultOutboundAction"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'.
Write-Host "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $registryName = "DisableNotifications"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'.
Write-Host "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $registryName = "LogFilePath"
    $registryValue = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'.
Write-Host "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $registryName = "LogFileSize"
    $registryValue = 16384

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'.
Write-Host "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $registryName = "LogDroppedPackets"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'.
Write-Host "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $registryName = "LogSuccessfulConnections"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'.
Write-Host "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $registryName = "EnableFirewall"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
Write-Host "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $registryName = "DefaultInboundAction"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'.
Write-Host "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $registryName = "DefaultOutboundAction"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'.
Write-Host "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $registryName = "DisableNotifications"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'
Write-Host "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $registryName = "LogFilePath"
    $registryValue = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

Start-Sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'.
Write-Host "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $registryName = "LogFileSize"
    $registryValue = 16384

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'.
Write-Host "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $registryName = "LogDroppedPackets"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
Write-Host "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $registryName = "LogSuccessfulConnections"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'.
Write-Host "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $registryName = "EnableFirewall"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'.
Write-Host "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $registryName = "DefaultInboundAction"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'.
Write-Host "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $registryName = "DisableNotifications"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'.
Write-Host "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $registryName = "AllowLocalPolicyMerge"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'.
Write-Host "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $registryName = "AllowLocalIPsecPolicyMerge"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'.
Write-Host "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $registryName = "LogFilePath"
    $registryValue = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'.
Write-Host "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $registryName = "LogFileSize"
    $registryValue = 16384

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'.
Write-Host "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $registryName = "LogDroppedPackets"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'.
Write-Host "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $registryName = "LogSuccessfulConnections"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'.
Write-Host "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $registryName = "NoLockScreenCamera"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'.
Write-Host "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $registryName = "NoLockScreenSlideshow"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'.
Write-Host "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    $registryName = "AllowInputPersonalization"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Allow Online Tips' is set to 'Disabled'.
Write-Host "Ensure 'Allow Online Tips' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "AllowOnlineTips"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'.
Write-Host "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
    $registryName = "RpcAuthnLevel"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'.
Write-Host "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"
    $registryName = "Start"
    $registryValue = 4

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Configure SMB v1 server' is set to 'Disabled'.
Write-Host "Ensure 'Configure SMB v1 server' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $registryName = "SMB1"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'.
Write-Host "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $registryName = "NodeType"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'.
Write-Host "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $registryName = "DisableIPSourceRouting"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'.
    Write-Host "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryName = "DisableIPSourceRouting"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'.
    Write-Host "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryName = "EnableICMPRedirect"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'.
    Write-Host "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryName = "KeepAliveTime"
    $registryValue = 300000

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'.
    Write-Host "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $registryName = "nonamereleaseondemand"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'.
    Write-Host "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryName = "PerformRouterDiscovery"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'.
    Write-Host "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $registryName = "SafeDllSearchMode"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'.
    Write-Host "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryName = "ScreenSaverGracePeriod"
    $registryValue = 5

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'.
    Write-Host "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
    $registryName = "TcpMaxDataRetransmissions"
    $registryValue = 3

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'.
    Write-Host "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryName = "TcpMaxDataRetransmissions"
    $registryValue = 3

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'.
    Write-Host "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
    $registryName = "WarningLevel"
    $registryValue = 90

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher.
    Write-Host "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" 
    $registryName = "DoHPolicy"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'.
    Write-Host "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" 
    $registryName = "EnableNetbios"
    $registryValue = 2

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Turn off multicast name resolution' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off multicast name resolution' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" 
    $registryName = "EnableMulticast"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Enable Font Providers' is set to 'Disabled'.
    Write-Host "Ensure 'Enable Font Providers' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
    $registryName = "EnableFontProviders"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Enable insecure guest logons' is set to 'Disabled'.
    Write-Host "Ensure 'Enable insecure guest logons' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" 
    $registryName = "AllowInsecureGuestAuth"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" 
    $registryName = "Disabled"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'.
    Write-Host "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" 
    $registryName = "NC_AllowNetBridge_NLA"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'.
    Write-Host "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" 
    $registryName = "NC_ShowSharedAccessUI"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'.
    Write-Host "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" 
    $registryName = "NC_StdDomainUserSetLocation"
    $registryValue = 1

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'.
   
#Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)').
    Write-Host "Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $registryName = "DisabledComponents"
    $registryValue = 255

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

start-sleep -Seconds 2

#Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'.
    Write-Host "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
    $registryName = "EnableRegistrars"
    $registryValue = 0

    # Function to create the registry key if it does not exist
    function New-RegistryKey {
        param (
            [string]$Path
        )
        try {
            if (-Not (Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Host "Registry key created at $Path"
            }
        } catch {
            Write-Host "Failed to create registry key at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Function to set the registry value
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [int]$Value
        )
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "Registry value $Name set to $Value at $Path"
        } catch {
            Write-Host "Failed to set registry value $Name at $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    # Main script logic
    try {
        # Attempt to set the registry value
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
    }

    # Additional registry settings
    $additionalSettings = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableFlashConfigRegistrar"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableUPnPRegistrar"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableInBand802DOT11Registrar"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableWPDRegistrar"; Value = 0 }
    )

    foreach ($setting in $additionalSettings) {
        try {
            Set-RegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value
        } catch {
            Write-Host "Attempting to create the registry key and set the value for $($setting.Name)..."
            New-RegistryKey -Path $setting.Path
            Set-RegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value
        }
    }

start-sleep -Seconds 2

#Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'.
#Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'.
#Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'.
#Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'.
#Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'.
#Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'.
#Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'.
#Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher.
#Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'.
#Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'.
#Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'.
#Ensure 'Turn off notifications network usage' is set to 'Enabled'.
#Ensure 'Remote host allows delegation of non- exportable credentials' is set to 'Enabled'.
#Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'.

