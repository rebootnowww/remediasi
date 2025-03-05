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
start-sleep -Seconds 1

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
start-sleep -Seconds 1

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

start-sleep -Seconds 1 

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

start-sleep -Seconds 1 

#Set enforce password history to 24
Write-Host "Set enforce password history to 24"
    net accounts /uniquepw:24
start-sleep -Seconds 1 

#Set minimum password age to 1 day
Write-Host "Set minimum password age to 1 day"
    net accounts /minpwage:1
start-sleep -Seconds 1 

#Set minimum password length to 14 characters
Write-Host "Set minimum password length to 14 characters"
    net accounts /minpwlen:14
start-sleep -Seconds 1 

#Set account lockout threshold to 5 invalid login attempts
Write-Host "Set account lockout threshold to 5 invalid login attempts"
    net accounts /lockoutthreshold:5
start-sleep -Seconds 1 

#Display the current password policy settings
Write-Host "Display the current password policy settings"
    net accounts
start-sleep -Seconds 1 

#Ensure Relax minimum password length limits is set to Enabled
Write-Host "Ensure Relax minimum password length limits is set to Enabled"
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SAM' -Name 'RelaxMinimumPasswordLengthLimits' -Value 1 -Type DWord
start-sleep -Seconds 1 

#Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts
Write-Host "Ensure Accounts: Block Microsoft accounts is set to Users cant add or log on with Microsoft accounts"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Value 3 -Type DWord
start-sleep -Seconds 1 

#Ensure Interactive logon: Dont display last signed-in is set to Enabled
Write-Host "Ensure Interactive logon: Dont display last signed-in is set to Enabled"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'dontdisplaylastusername' -Value 1
start-sleep -Seconds 1 

#Ensure Interactive logon: Machine inactivity limit is set to 900 or fewer second(s), but not 0
Write-Host "Ensure Interactive logon: Machine inactivity limit is set to 900 or fewer second(s), but not 0"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord
start-sleep -Seconds 1 

#Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher
Write-Host "Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher"
    Set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'scremoveoption' -Value 2 
start-sleep -Seconds 1 

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

start-sleep -Seconds 1 

#Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled
Write-Host "Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled"
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord
start-sleep -Seconds 1 

#Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop
Write-Host "Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop"
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
start-sleep -Seconds 1 

#Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests
Write-Host "Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests"
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0
start-sleep -Seconds 1 

#Ensure Include command line in process creation events is set to Enabled
Write-Host "Ensure Include command line in process creation events is set to Enabled"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
start-sleep -Seconds 1 

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

start-sleep -Seconds 1 

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

#Configure 'Interactive logon: Message text for users attempting to log on'.
Write-Host "Configure 'Interactive logon: Message text for users attempting to log on'."
    # Define the message text
    $messageText = "This system is for authorized users only. Unauthorized access is prohibited."

    # Set the message text
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -Value $messageText
    start-sleep -Seconds 1

#Configure 'Interactive logon: Message title for users attempting to log on'.
Write-Host "Configure 'Interactive logon: Message title for users attempting to log on'."
    # Define the message title
    $messageTitle = "Warning"

    # Set the message title
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Value $messageTitle
    start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

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

start-sleep -Seconds 1

#Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'.
    Write-Host "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
    $registryName = "DisableWcnUi"
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

start-sleep -Seconds 1

#Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'.
    Write-Host "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $registryName = "fMinimizeConnections"
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

start-sleep -Seconds 1

#Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'.
    Write-Host "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "RegisterSpoolerRemoteRpcEndPoint"
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

start-sleep -Seconds 1

#Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'.
    Write-Host "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "RedirectionGuardPolicy"
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

start-sleep -Seconds 1

#Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'.
    Write-Host "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "RpcAuthentication"
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

start-sleep -Seconds 1

#Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'.
    Write-Host "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "RpcProtocols"
    $registryValue = 7

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

start-sleep -Seconds 1

#Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher.
    Write-Host "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "ForceKerberosForRpc"
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

start-sleep -Seconds 1

#Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'.
    Write-Host "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "RpcTcpPort"
    $registryValue = 65535

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

start-sleep -Seconds 1

#Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'.
    Write-Host "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $registryName = "RestrictDriverInstallationToAdministrators"
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

start-sleep -Seconds 1

#Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'.
    Write-Host "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "CopyFilesPolicy"
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

start-sleep -Seconds 1

#Ensure 'Turn off notifications network usage' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off notifications network usage' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $registryName = "NoCloudApplicationNotification"
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

start-sleep -Seconds 1

#Ensure 'Remote host allows delegation of non- exportable credentials' is set to 'Enabled'.
    Write-Host "Ensure 'Remote host allows delegation of non- exportable credentials' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
    $registryName = "AllowProtectedCreds"
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

start-sleep -Seconds 1

#Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'.
    Write-Host "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $registryName = "EnableVirtualizationBasedSecurity"
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

start-sleep -Seconds 1

#Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher.
    Write-Host "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $registryName = "RequirePlatformSecurityFeatures"
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

start-sleep -Seconds 1

#Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'.
    Write-Host "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $registryName = "HyperVisorEnforcedCodeIntegrity"
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

start-sleep -Seconds 1

#Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'.
    Write-Host "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $registryName = "HVCIMATRequired"
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

start-sleep -Seconds 1

#Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'.
    Write-Host "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $registryName = "ConfigureSystemGuardLaunch"
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

start-sleep -Seconds 1

#Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'.
    Write-Host "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
    $registryName = "PreventDeviceMetadataFromNetwork"
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

start-sleep -Seconds 1

#Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'.
    Write-Host "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
    $registryName = "DriverLoadPolicy"
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

start-sleep -Seconds 1

#Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'.
    Write-Host "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    $registryName = "NoBackgroundPolicy"
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

start-sleep -Seconds 1

#Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'.
    Write-Host "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    $registryName = "NoGPOListChanges"
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

start-sleep -Seconds 1
#Ensure 'Continue experiences on this device' is set to 'Disabled'.
    Write-Host "Ensure 'Continue experiences on this device' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "EnableCdp"
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

start-sleep -Seconds 1

#Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "DisableWebPnPDownload"
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

start-sleep -Seconds 1

#Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
    $registryName = "PreventHandwritingDataSharing"
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

start-sleep -Seconds 1

#Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
    $registryName = "PreventHandwritingErrorReports"
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

start-sleep -Seconds 1

#Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
    $registryName = "ExitOnMSICW"
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

start-sleep -Seconds 1

#Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "NoWebServices"
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

start-sleep -Seconds 1

#Ensure 'Turn off printing over HTTP' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off printing over HTTP' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryName = "DisableHTTPPrinting"
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

start-sleep -Seconds 1

#Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
    $registryName = "NoRegistration"
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

start-sleep -Seconds 1

#Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
    $registryName = "DisableContentFileUpdates"
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

start-sleep -Seconds 1

#Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off the 'Order Prints' picture task' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "NoOnlinePrintsWizard"
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

start-sleep -Seconds 1

#Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off the 'Publish to Web' task for files and folders' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "NoPublishingWizard"
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

start-sleep -Seconds 1

#Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
    $registryName = "CEIP"
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

start-sleep -Seconds 1

#Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    $registryName = "CEIPEnable"
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

start-sleep -Seconds 1

#Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
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

start-sleep -Seconds 1

#Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'.
    Write-Host "Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
    $registryName = "DeviceEnumerationPolicy"
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

start-sleep -Seconds 1

#Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'.
    Write-Host "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "AllowCustomSSPsAPs"
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

start-sleep -Seconds 1

#Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'.
    Write-Host "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'."
    # Define the registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $registryName = "RunAsPPL"
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

start-sleep -Seconds 1

#Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'.
    Write-Host "Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $registryName = "AllowCloudSearch"
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

start-sleep -Seconds 1

#Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'.
    Write-Host "Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $registryName = "AllowTelemetry"
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

start-sleep -Seconds 1

#Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'.
    Write-Host "Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
    $registryName = "AllowMessageSync"
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

start-sleep -Seconds 1

#Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'.
    Write-Host "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryName = "MSAOptional"
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

start-sleep -Seconds 1

#Ensure 'Allow UI Automation redirection' is set to 'Disabled'.
    Write-Host "Ensure 'Allow UI Automation redirection' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "EnableUiaRedirection"
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

start-sleep -Seconds 1

#Ensure 'Allow Use of Camera' is set to 'Disabled'.

    Write-Host "Ensure 'Allow Use of Camera' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
    $registryName = "AllowCamera"
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

start-sleep -Seconds 1

#Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'.
    Write-Host "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $registryName = "AllowWindowsInkWorkspace"
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

start-sleep -Seconds 1

#Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'.
    Write-Host "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
    $registryName = "DCSettingIndex"
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

start-sleep -Seconds 1

#Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'.
    Write-Host "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
    $registryName = "ACSettingIndex"
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

start-sleep -Seconds 1

#Ensure 'Allow search highlights' is set to 'Disabled'.
    Write-Host "Ensure 'Allow search highlights' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $registryName = "EnableDynamicContentInWSB"
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

start-sleep -Seconds 1

#Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'.

    Write-Host "Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $registryName = "AllowSuggestedAppsInWindowsInkWorkspace"
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

start-sleep -Seconds 1

#Ensure 'Allow upload of User Activities' is set to 'Disabled'.
    Write-Host "Ensure 'Allow upload of User Activities' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "UploadUserActivities"
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

start-sleep -Seconds 1

#Ensure 'Always prompt for password upon connection' is set to 'Enabled'.
    Write-Host "Ensure 'Always prompt for password upon connection' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fPromptForPassword"
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

start-sleep -Seconds 1

#Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'.
    Write-Host "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
    $registryName = "MaxSize"
    $registryValue = 32768

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

start-sleep -Seconds 1

#Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'.
    Write-Host "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
    $registryName = "DisableUserAuth"
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

start-sleep -Seconds 1

#Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'.
    Write-Host "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "BlockUserFromShowingAccountDetailsOnSignin"
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

start-sleep -Seconds 1

#Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'.
    Write-Host "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
    $registryName = "ExploitGuard_ASR_Rules"
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

start-sleep -Seconds 1

#Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'.
    Write-Host "Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $registryName = "DisableEnterpriseAuthProxy"
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

start-sleep -Seconds 1

#Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'.
    Write-Host "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $registryName = "ScheduledInstallDay"
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

start-sleep -Seconds 1

#Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'.
    Write-Host "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fAllowToGetHelp"
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

start-sleep -Seconds 1

#Ensure 'Configure Watson events' is set to 'Disabled'.
    Write-Host "Ensure 'Configure Watson events' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
    $registryName = "DisableGenericRePorts"
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

start-sleep -Seconds 1

#Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'.
    Write-Host "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $registryName = "PUAProtection"
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

start-sleep -Seconds 1

#Ensure 'Turn on e-mail scanning' is set to 'Enabled'.
    Write-Host "Ensure 'Turn on e-mail scanning' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
    $registryName = "DisableEmailScanning"
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

start-sleep -Seconds 1

#Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'.
    Write-Host "Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $registryName = "EnableTranscripting"
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

start-sleep -Seconds 1

#Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'.
    Write-Host "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $registryName = "EnableScriptBlockLogging"
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

start-sleep -Seconds 1

#Ensure 'Turn off the advertising ID' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off the advertising ID' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    $registryName = "DisabledByGroupPolicy"
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

start-sleep -Seconds 1

#Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'.
    Write-Host "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "PreXPSP2ShellProtocolBehavior"
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

start-sleep -Seconds 1

#Ensure 'Turn off picture password sign-in' is set to 'Enabled'.	
    Write-Host "Ensure 'Turn off picture password sign-in' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "BlockDomainPicturePassword"
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

start-sleep -Seconds 1

#Ensure 'Turn off location' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off location' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    $registryName = "DisableLocation"
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

start-sleep -Seconds 1

#Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
    $registryName = "PreventHandwritingErrorReports"
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

start-sleep -Seconds 1

#Ensure 'Turn off cloud optimized content' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off cloud optimized content' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryName = "DisableCloudOptimizedContent"
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

start-sleep -Seconds 1

#Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryName = "DisableConsumerAccountStateContent"
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

start-sleep -Seconds 1

#Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "DisableLockScreenAppNotifications"
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

start-sleep -Seconds 1

#Ensure 'Turn off Push To Install service' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Push To Install service' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
    $registryName = "DisablePushToInstall"
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

start-sleep -Seconds 1

#Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryName = "DisableWindowsConsumerFeatures"
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

start-sleep -Seconds 1

#Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'.
    Write-Host "Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
    $registryName = "NoGenTicket"
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

start-sleep -Seconds 1

#Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'.
    Write-Host "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "NoDriveTypeAutoRun"
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

start-sleep -Seconds 1

#Ensure 'Toggle user control over Insider builds' is set to 'Disabled'.
    Write-Host "Ensure 'Toggle user control over Insider builds' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
    $registryName = "AllowBuildPreview"
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

start-sleep -Seconds 1

#Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'.
    Write-Host "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
    $registryName = "MaxSize"
    $registryValue = 32768

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

start-sleep -Seconds 1

#Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'.
    Write-Host "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
    $registryName = "MaxSize"
    $registryValue = 32768

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

start-sleep -Seconds 1

#Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'.
    Write-Host "Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "MaxDisconnectionTime"
    $registryValue = 60000

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

start-sleep -Seconds 1

#Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'.
    Write-Host "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "MaxIdleTime"
    $registryValue = 900000

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

start-sleep -Seconds 1

#Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'.
    Write-Host "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $registryName = "NoAutorun"
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

start-sleep -Seconds 1

#Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'.
    Write-Host "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "MinEncryptionLevel"
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

start-sleep -Seconds 1

#Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'.
    Write-Host "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
    $registryName = "MaxSize"
    $registryValue = 196608

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

start-sleep -Seconds 1

#Ensure 'Scan removable drives' is set to 'Enabled'.
    Write-Host "Ensure 'Scan removable drives' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
    $registryName = "DisableRemovableDriveScanning"
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

start-sleep -Seconds 1

#Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Disabled' (DC Only).
    Write-Host "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Disabled' (DC Only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $registryName = "LsaCfgFlags"
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

start-sleep -Seconds 1

#Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'.
    # Define the registry path and values
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
    $registryName1 = "DevicePKInitBehavior"
    $registryValue1 = 0
    $registryName2 = "DevicePKInitEnabled"
    $registryValue2 = 1

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
        # Attempt to set the registry values
        Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
        Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
    } catch {
        # If setting the values fails, create the key and then set the values
        Write-Host "Attempting to create the registry key and set the values..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
        Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
    }

start-sleep -Seconds 1

#Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'.
    Write-Host "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $registryName1 = "DeferQualityUpdates"
    $registryValue1 = 1
    $registryName2 = "DeferQualityUpdatesPeriodInDays"
    $registryValue2 = 0

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
        # Attempt to set the registry values
        Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
        Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
    } catch {
        # If setting the values fails, create the key and then set the values
        Write-Host "Attempting to create the registry key and set the values..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
        Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
    }

start-sleep -Seconds 1

#Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'.
    write-host "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'."     
    # Define the registry path and value
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $registryName1 = "DeferFeatureUpdates"
        $registryValue1 = 1
        $registryName2 = "DeferFeatureUpdatesPeriodInDays"
        $registryValue2 = 180
    
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
            # Attempt to set the registry values
            Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
            Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
        } catch {
            # If setting the values fails, create the key and then set the values
            Write-Host "Attempting to create the registry key and set the values..."
            New-RegistryKey -Path $registryPath
            Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
            Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
        }
    
 start-sleep -Seconds 1

 #Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only).
    Write-Host "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
    $registryName = "RestrictRemoteClients"
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

start-sleep -Seconds 1

#Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'.
    Write-Host "Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fSingleSessionPerUser"
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

start-sleep -Seconds 1

#Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'.
    Write-Host "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "UserAuthentication"
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

start-sleep -Seconds 1

#Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'.
    Write-Host "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "SecurityLayer"
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

start-sleep -Seconds 1

#Ensure 'Require secure RPC communication' is set to 'Enabled'.
    Write-Host "Ensure 'Require secure RPC communication' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fEncryptRPCTraffic"
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

start-sleep -Seconds 1

#Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'.
    Write-Host "Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
    $registryName = "RequirePinForPairing"
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

start-sleep -Seconds 1

#Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'.
    Write-Host "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    $registryName = "ACSettingIndex"
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

start-sleep -Seconds 1

#Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'.
    Write-Host "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    $registryName = "DCSettingIndex"
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

start-sleep -Seconds 1

#Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' (MS only).
    Write-Host "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $registryName = "fBlockNonDomain"
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

start-sleep -Seconds 1

#Ensure 'Prevent users from modifying settings' is set to 'Enabled'.
    Write-Host "Ensure 'Prevent users from modifying settings' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
    $registryName = "DisallowExploitProtectionOverride"
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

start-sleep -Seconds 1

#Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'.
    Write-Host "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
    $registryName = "EnableNetworkProtection"
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

start-sleep -Seconds 1

#Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'.
    Write-Host "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    $registryName = "DisableFileSyncNGSC"
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

start-sleep -Seconds 1

#Ensure 'Prevent downloading of enclosures' is set to 'Enabled'.
    Write-Host "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
    $registryName = "DisableEnclosureDownload"
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

start-sleep -Seconds 1

#Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only).
    Write-Host "Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $registryName = "PasswordLength"
    $registryValue = 15

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

start-sleep -Seconds 1

#Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only).
    Write-Host "Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $registryName = "PasswordComplexity"
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

start-sleep -Seconds 1

#Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only).
Write-Host "Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $registryName = "PasswordAgeDays"
    $registryValue = 30

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

start-sleep -Seconds 1

#Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'.
    Write-Host "Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
    $registryName = "DisableQueryRemoteServer"
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

start-sleep -Seconds 1

#Ensure 'Manage preview builds' is set to 'Disabled'.
    Write-Host "Ensure 'Manage preview builds' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $registryName = "ManagePreviewBuildsPolicyValue"
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

start-sleep -Seconds 1

#Ensure 'Limit Dump Collection' is set to 'Enabled'.
    Write-Host "Ensure 'Limit Dump Collection' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $registryName = "LimitDumpCollection"
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

start-sleep -Seconds 1

#Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'.
    Write-Host "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $registryName = "LimitDiagnosticLogCollection"
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

start-sleep -Seconds 1

#Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'.
    Write-Host "Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
    $registryName = "\\*\NETLOGON"
    $registryValue = "RequireMutualAuthentication=1, RequireIntegrity=1"
    $registryName2 = "\\*\SYSVOL"
    $registryValue2 = "RequireMutualAuthentication=1, RequireIntegrity=1"

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
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force -ErrorAction Stop
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
        Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
    } catch {
        # If setting the value fails, create the key and then set the value
        Write-Host "Attempting to create the registry key and set the value..."
        New-RegistryKey -Path $registryPath
        Set-RegistryValue -Path $registryPath -Name $registryName -Value $registryValue
        Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
    }

start-sleep -Seconds 1

#Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'.
    Write-Host "Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
    $registryName = "ScenarioExecutionEnabled"
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

start-sleep -Seconds 1

#Ensure 'Enable file hash computation feature' is set to 'Enabled'.
    Write-Host "Ensure 'Enable file hash computation feature' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
    $registryName = "EnableFileHashComputation"
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

start-sleep -Seconds 1

#Ensure 'Enable Windows NTP Client' is set to 'Enabled'.
    Write-Host "Ensure 'Enable Windows NTP Client' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
    $registryName = "Enabled"
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

start-sleep -Seconds 1

#Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only).
    Write-Host "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
    $registryName = "EnableAuthEpResolution"
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

start-sleep -Seconds 1

#Ensure 'Enable OneSettings Auditing' is set to 'Enabled'.
    Write-Host "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $registryName = "EnableOneSettingsAuditing"
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

start-sleep -Seconds 1

#Ensure 'Enable MPR notifications for the system' is set to 'Disabled'.
    Write-Host "Ensure 'Enable MPR notifications for the system' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryName = "EnableMPR"
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

start-sleep -Seconds 1

#Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only).
    Write-Host "Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $registryName = "AdmPwdEnabled"
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

start-sleep -Seconds 1

#Ensure 'Enable App Installer' is set to 'Disabled'.
    Write-Host "Ensure 'Enable App Installer' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appinstaller"
    $registryName = "EnableAppInstaller"
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

start-sleep -Seconds 1

#Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'.
    Write-Host "Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $registryName = "EnableMSAppInstallerProtocol"
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

start-sleep -Seconds 1

#Ensure 'Enable App Installer Hash Override' is set to 'Disabled'.
    Write-Host "Ensure 'Enable App Installer Hash Override' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $registryName = "EnableHashOverride"
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

start-sleep -Seconds 1

#Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'.
Write-Host "Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $registryName = "EnableExperimentalFeatures"
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

start-sleep -Seconds 1

#Ensure 'Do not use temporary folders per session' is set to 'Disabled'.
    Write-Host "Ensure 'Do not use temporary folders per session' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "PerSessionTempDir"
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

start-sleep -Seconds 1

#Ensure 'Do not show feedback notifications' is set to 'Enabled'.
    Write-Host "Ensure 'Do not show feedback notifications' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $registryName = "DoNotShowFeedbackNotifications"
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

start-sleep -Seconds 1

#Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'.
    Write-Host "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "DontEnumerateConnectedUsers"
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

start-sleep -Seconds 1

#Ensure 'Do not display the password reveal button' is set to 'Enabled'.
    Write-Host "Ensure 'Do not display the password reveal button' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
    $registryName = "DisablePasswordReveal"
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

start-sleep -Seconds 1

#Ensure 'Do not display network selection UI' is set to 'Enabled'.
    Write-Host "Ensure 'Do not display network selection UI' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryName = "DontDisplayNetworkSelectionUI"
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

start-sleep -Seconds 1

#Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'.
    Write-Host "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "DeleteTempDirsOnExit"
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

start-sleep -Seconds 1

#Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'.
    Write-Host "Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fDisablePNPRedir"
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

start-sleep -Seconds 1

#Ensure 'Do not allow passwords to be saved' is set to 'Enabled'.
    Write-Host "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "DisablePasswordSaving"
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

start-sleep -Seconds 1

#Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only).
    Write-Host "Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $registryName = "PwdExpirationProtectionEnabled"
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

start-sleep -Seconds 1

#Ensure 'Do not allow location redirection' is set to 'Enabled'.
    Write-Host "Ensure 'Do not allow location redirection' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fDisableLocationRedir"
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

start-sleep -Seconds 1

#Ensure 'Do not allow drive redirection' is set to 'Enabled'.
    Write-Host "Ensure 'Do not allow drive redirection' is set to 'Enabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $registryName = "fDisableCdm"
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

start-sleep -Seconds 1

#Ensure 'Allow Remote Shell Access' is set to 'Disabled'.
    Write-Host "Ensure 'Allow Remote Shell Access' is set to 'Disabled'."
    # Define the registry path and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
    $registryName = "AllowRemoteShellAccess"    
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

start-sleep -Seconds 1

#Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured.
    Write-Host "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured."
    # Define the registry path and values
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
        $registryNames = @(
            "26190899-1602-49E8-8B27-eB1D0A1CE869",
            "3B576869-A4EC-4529-8536-B80A7769E899",
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
            "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
            "9E6C4E1F-7D60-472F-bA1A-A39EF669E4B2",
            "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
            "D3E037E1-3EB8-44C8-A917-57927947596D",
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
        )
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
            # Ensure the registry key exists
            New-RegistryKey -Path $registryPath

            # Attempt to set the registry values
            foreach ($name in $registryNames) {
                Set-RegistryValue -Path $registryPath -Name $name -Value $registryValue
            }
        } catch {
            Write-Host "An error occurred while setting the registry values. Error: $($_.Exception.Message)" -ForegroundColor Red
        }

start-sleep -Seconds 1

#Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'.
        write-host "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'."
        # Define the registry path and values
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            $registryName1 = "EnableSmartScreen"
            $registryValue1 = 1
            $registryName2 = "ShellSmartScreenLevel"
            $registryValue2 = "Block"

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
                    [Object]$Value
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
                # Ensure the registry key exists
                New-RegistryKey -Path $registryPath

                # Attempt to set the registry values
                Set-RegistryValue -Path $registryPath -Name $registryName1 -Value $registryValue1
                Set-RegistryValue -Path $registryPath -Name $registryName2 -Value $registryValue2
            } catch {
                Write-Host "An error occurred while setting the registry values. Error: $($_.Exception.Message)" -ForegroundColor Red
            }

start-sleep -Seconds 1

#Ensure 'Disallow Digest authentication' is set to 'Enabled'.
            write-host "Ensure 'Disallow Digest authentication' is set to 'Enabled'."
            # Define the registry path and value
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
            $registryName = "AllowDigest" 
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

start-sleep -Seconds 1

#Ensure 'Configure validation of ROCA-vulnerable WHfB keys during authentication' is set to 'Enabled: Audit' or higher (DC only).
            write-host "Ensure 'Configure validation of ROCA-vulnerable WHfB keys during authentication' is set to 'Enabled: Audit' or higher (DC only)."
            # Define the registry path and value
            $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"
            $registryName = "SamNGCKeyROCAValidation"
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

start-sleep -Seconds 1

#Ensure 'Disable OneSettings Downloads' is set to 'Enabled'.
            write-host "Ensure 'Disable OneSettings Downloads' is set to 'Enabled'."
            # Define the registry path and value
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            $registryName = "DisableOneSettingsDownloads"
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

start-sleep -Seconds 1

#Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'.
            write-host "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'."
            # Define the registry path and value
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
            $registryName = "NoAutoplayfornonVolume"
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

start-sleep -Seconds 1

#Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'.
            write-host "Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'."
            # Define the registry path and value
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
            $registryName = "BlockUserInputMethodsForSignIn"
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

start-sleep -Seconds 1

#Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'.
            write-host "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'."
            # Define the registry path and value
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
            $registryName = "EnhancedAntiSpoofing"
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

start-sleep -Seconds 1