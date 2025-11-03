    - name: Create RDP User Account
      run: |
        Write-Host "Creating RDP user account..."
        
        # Generate secure random password (PowerShell 7+ compatible)
        Add-Type -AssemblyName System.Security
        $length = 16
        $allowedChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+='
        $password = -join ((1..$length) | ForEach-Object { $allowedChars[(Get-Random -Maximum $allowedChars.Length)] })
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        
        # Create or update user
        try {
            New-LocalUser -Name "RDPUser" -Password $securePassword -FullName "RDP User" -Description "Temporary RDP user for GitHub Actions" -AccountNeverExpires -ErrorAction Stop
            Write-Host "User RDPUser created successfully"
        }
        catch {
            Write-Host "User may already exist, updating password..."
            Set-LocalUser -Name "RDPUser" -Password $securePassword -ErrorAction Stop
        }
        
        # Add to required groups
        Add-LocalGroupMember -Group "Administrators" -Member "RDPUser" -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member "RDPUser" -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Users" -Member "RDPUser" -ErrorAction SilentlyContinue
        
        # Store credentials in environment (for later steps)
        Add-Content -Path $env:GITHUB_ENV -Value "RDP_USERNAME=RDPUser"
        Add-Content -Path $env:GITHUB_ENV -Value "RDP_PASSWORD=$password"
        
        Write-Host "User account setup completed successfully."
