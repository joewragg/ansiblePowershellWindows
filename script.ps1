#run with `powershell -ExecutionPolicy Bypass -File script.ps1`

#vars
$username = 'ansible'
$plainPassword = "password"
$certPath = "cert.pem"
$password = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force


#cert
$cert = @'
-----BEGIN CERTIFICATE-----
MIIC9zCCAd+gAwIBAgIUbSNkFmH8w+QYGd/izi62zuCzNXkwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHYW5zaWJsZTAeFw0yMDEyMTExNDQ3MjFaFw0zMDEyMDkx
NDQ3MjFaMBIxEDAOBgNVBAMMB2Fuc2libGUwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDAKN0mXXhLJEDtpWFUNeT87np1m5IfXadiQn4qDopkwm17k5Wj
l67kSAzJJHF3NQQKDMqTRzvkZBnmkmU6llbLOazEF6aY88RE9QUJGrEQoUS9WA+P
8NGik5qDYXeGQa8gTCBsPOSkmyp37wvzWBhAQ4ViO2RC2HxN2ckupU8ZHkFNblCj
fMyhcDHLikdL1xTKFiNZCtxtxwx65zT6C4lYroGfq1sUitDAbraNEL5cm89xt4Qx
Qhhc+KIiLUaT74ATnvY8+XiHESDB4OemVo+kW6iKicXBtTH6ZPVZspVHvo52TqWX
o3mBJnWRjo4CkkfqwkwcRiEOwlwiH8MthkVJAgMBAAGjRTBDMBMGA1UdJQQMMAoG
CCsGAQUFBwMCMCwGA1UdEQQlMCOgIQYKKwYBBAGCNxQCA6ATDBFhbnNpYmxlQGxv
Y2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAggxsWB+GYHC1k8qMfbTRO7hwS1+s
bO6kmwPxvZD5HUj5V9VVuI+o4Ai2/4pbU3QtIzPA3fNUlHfKd/NcA5pfTzotFzHd
nDuTfZC+rWAmBjgJI7o67wgCT418sl+WZIrTuLMk7qTV6Mho02K4sANjDoYFQafP
Y2GIydNl8dLD9utovjwVcQ1xXnU0e8E/1h3WsZbIlOjs76Hc0Y1He2PhLfIT432Q
TdOuegiAWwBdPEMylVfo8+5G3mIdxn3zLBMqLHqbO4WXicflmg7gmkJrTRjsad6y
s719MW0jLstwUUyrH/58ZYGTTaTnGoqRBHrEf9QH43wIHtjjD15nGwdD+A==
-----END CERTIFICATE-----
'@


#create user
if (-not (Get-LocalUser -Name $username -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $username
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $password
    }
    $null = New-LocalUser @newUserParams
	Get-LocalUser -Name $username | Add-LocalGroupMember -Group 'Administrators'
}



#setup WinRM service
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true


#put cert in temp file
$cert | Out-File $certPath -NoNewline


#import cert
$cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($certPath)

$store_name = [System.Security.Cryptography.X509Certificates.StoreName]::Root
$store_location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
$store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store_name, $store_location
$store.Open("MaxAllowed")
$store.Add($cert)
$store.Close()

$store_name = [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople
$store_location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
$store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store_name, $store_location
$store.Open("MaxAllowed")
$store.Add($cert)
$store.Close()


#map cert to account
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password
$thumbprint = (Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Subject -eq "CN=$username" }).Thumbprint
if ((Get-ChildItem -Path WSMan:\localhost\ClientCertificate) -eq $null) {                                 
	New-Item -Path WSMan:\localhost\ClientCertificate `
		-Subject "$username@localhost" `
		-URI * `
		-Issuer $thumbprint `
		-Credential $credential `
		-Force
}

#create server cert
$hostname = (hostname)
if (-not ((Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$hostname" }) | Test-Path) ){
	$serverCert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation 'Cert:\LocalMachine\My'
}else{
	$serverCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$hostname" })
}


#create winrm listener
$httpsListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -match 'Transport=HTTPS' }

## If not listeners are defined at all or no listener is configured to work with
## the server cert created, create a new one with a Subject of the computer's host name
## and bound to the server certificate.
if ((-not $httpsListeners) -or -not (@($httpsListeners).where( { $_.CertificateThumbprint -ne $serverCert.Thumbprint }))) {
    $newWsmanParams = @{
        ResourceUri = 'winrm/config/Listener'
        SelectorSet = @{ Transport = "HTTPS"; Address = "*" }
        ValueSet    = @{ Hostname = $hostName; CertificateThumbprint = $serverCert.Thumbprint }
        # UseSSL = $true
    }
    $null = New-WSManInstance @newWsmanParams
}

# open port on firewall
 $ruleDisplayName = 'Windows Remote Management (HTTPS-In)'
 if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore)) {
     $newRuleParams = @{
         DisplayName   = $ruleDisplayName
         Direction     = 'Inbound'
         LocalPort     = 5986
         RemoteAddress = 'Any'
         Protocol      = 'TCP'
         Action        = 'Allow'
         Enabled       = 'True'
         Group         = 'Windows Remote Management'
     }
     $null = New-NetFirewallRule @newRuleParams
 }