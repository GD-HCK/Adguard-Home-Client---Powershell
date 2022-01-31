# Readme

## AdGuard Home Powershell Client


## Getting Started Guide
* `Open Powershell`

    ```powershell
    # Run the below as administrator in Powershell 5.1 only for windows server
    Set-Location -Path 'C:\LocationOfRepository'
    $Username = 'admin'
    $Password = Read-Host -Prompt "Type your Adguard Password" -AsSecureString
    $Credentials = [pscredential]::new($username,$password)
    $URL = 'https://adguard.example.com'
    .\AdGuardClient.ps1 -URL $URL -Credentials $Credentials
    ```

## TODO
Issue | Resolved |
--- | --- | 
Initial Prototype and structure | ~~`Done`~~ |
Complete All Api Endpoints | `In Progress`
Read Api Definitions From Yaml | `To Do` |