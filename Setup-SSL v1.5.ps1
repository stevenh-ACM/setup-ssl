
<#
.SYNOPSIS
    Provision HTTPS and configure IIS for a typical demo environment for Acumatica ERP

.DESCRIPTION
    Script to provision a self signed certificate. It's then copied (not moved) to the Cert Storage in the
    Root and WebHosting folders.
    Script then continues to provision a web site binding for HTTPS and then binds the new cert created above.

    Most Browsers will accept this cert as it has all parameters set. This script is a replacement for 
    the use of the IIS Manager Self-SignedCertificate feature which create defective certs for modern browsers.

    ***********************************************************************************************************************************************************
    High level explanation of what's going on:

    *Browswer(local PC xyz)                      Server (same local PC xyz)
      HTTPS Req sent                 ------>     Received

    *Public Key Received             <------     Send Public asymetrical Key for PC to encapsulate it's ssl cert
      The Browser verifies Key as to trust remote server (third party trusted CA's are used here skipping compliations here)
    
    *Public Key(bonded Local Cert)   ------>     Received, Local Private asymetrical Key used for unwrapping remote PC's bond cert
                                     X error
      Browser inspects/verifies cert.
    
    1) most browsers fail at this point of inspection/verification since there's no trusted CA and self-signed server are configured to not accepted. Moreover,
       there's no local trusted cert in the ROOT folder that either is a copy or chained in the local PC cert store. The chain can be for xyz.yourdomain.com certs for
       domain joined PC's. e.g. dev-xyz.acumatica.com
        
       Modern browsers can be configured to ignore this situation but continue to harden their configuration as standards mature for TLS 1.3.This is not the 
       answer long term. Using localhost is also not available any more because unless your PC has the name localhost (which it can not) the process does not support it.
    
    2) The trick is to satisfy the base condition the browswers require. This is accomplished by placing a copy of the created self signed cert (client)
       into the Root folder. Since this is a browswer issue there's no need to place the cert copy into the WebHosting folder.

    3) The error message if it occurs is the result of the check that the cert's (SAN) name(s) is/are not the local PC's name nor is it chained to anything.
       Ignoring this error message results in a fall back to HTTP. 

    *Connection Established         <------     Send HTTPS connection OK using local Cert to symetrically encrypt transmission
      (lock apppears on Address bar in browser and all further transmission to this URL are encrytped with the cert bonded to the web server (and all virtual servers hanging off of it)

    If step 1 fails there is no HTTPS connection, no secure transmissions. 
    If all steps succeed - all is ok. HTTPS is being used with the TLS 1.2 protocol

.PARAMETER computerName
    The parameter computerName is the actual local PC's name. Found settings -> system manually.

.PARAMETER domainName
    The parameter domainName is used only if the PC is domain joined. Many if not most business PC's are either joined to a work domian using Active Directory or
    to an AZURED domain using there Microsoft 365 Exchange domain which could be the companies own domain name but AZURED is used not a on premises AD.

    If this is a personal PC the chances are that it is NOT domain joined so this parameter will return NULL.

.PARAMETER webSiteName
    It's assumed by this script that the demo instance has been created as a virtual website under the default web site namely "Default Web Site" created by IIS when installed.#>

<#============================================================================

-> Copy this line and execute in a powershell with administrator privilege <-
 
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

============================================================================#>

# pass true to set cert to FQN or Computer name instead of localhost

param
(
    [ValidateSet($True, $False, 0, 1)]
    [ValidateNotNullOrEmpty()]
    [Bool]$useFQN = $False
)

<#
.EXAMPLE
    1) execute command 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass' in an administrative privleged powershell session
    2) Open script in an administrative privleged powershell session.

.COMMMENT
    Prior to running script, the local PC OS needs to trust scripts in general and the default for most it not to. The script in 2) above will error out if 1) above is 
    is not taken first. only answer yes to the prompt.

.NOTES
    Author: Steven Houglum
    Last Edit: 2020-10-27
           "Ver 1.0" # - initial release
           "Ver 1.1" # - fixed cert creation 
           "Ver 1.2" # - added FQN
           "Ver 1.3" # - fixed bugs
           "Ver 1.4" # - added localhost #>
$version = "Ver 1.5" # - added parm to decide on FWN or localhost
$author = "Steven Houglum"

clear-host
Write-Warning "`n`r`t=====================================================================`n`r
`tCopyright © 2020 $author $Version

`tThis software is strickly ""not of sale"". Permission is hereby granted,
`tfree of charge, to any person obtaining a copy of this software and associated
`tdocumentation files (the 'Software'), to deal in the Software without
`trestriction, including without limitation the rights to use, copy, modify,
`tmerge, publish and distribute and to permit persons to whom the Software is
`tfurnished to do so, subject to the following conditions:`n
`tThe above copyright notice and this permission notice shall be included in all 
`tcopies or substantial portions of the Software.`n
`tTHE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
`tIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
`tFOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
`tCOPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
`tIN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION`
`tWITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`n
`tI understand and accept this Copyright and all Terms herein.`n`r
`t=====================================================================`r`n`n"  -WarningAction Inquire


import-module webadministration      # web admin modules

$WriteFlag = $true                   # writing to host/consol set to on (true)
$MyPath = $env:windir
$Logfile = $MyPath + "\Logs\$(gc env:computername).log"

# remove log file if it exists
Remove-Item $Logfile -ErrorAction SilentlyContinue

<# Logging and writeing to host #>
Function LogWrite
{
   Param ([string]$logstring)
   Add-content $Logfile -value $logstring
   if($WriteFlag) {Write-Host $logstring}
}

<# Parameters #>

$dateTime = Get-Date                 #get date and time
$computerName = $Env:Computername    #get computer name of local computer e.g. acumaticaDemo
$domainName = $Env:UserDnsDomain     #get domain name if it exists for local computer e.g. acumatica.com
$webSiteName = "Default Web Site"    #IIS web site name created by default and typically used in Acumatica ERP Wizard
$FQN = $computerName+'.'+$domainName #Fully Qualified Name xxx.domain.com
$Local = "localhost"                 #localhost is default friendly name for certificate

<# Continue? #>
if($useFQN)
    {
        #clear-host
        write-warning "`n`t=====================================================================`n`r
`t$useFQN selected. A fully qualified name (FQN) will be used for a new self-signed certificate.
`tBe warned that the local machine certificates will be modified. This may cause errant machine behaviors.`n`r
`t=====================================================================`n`r" -WarningAction Inquire
    }
  else
    {
        #clear-host
        write-warning "`n`t=====================================================================`n`r
`tA default parameter of null, '0' or '$useFQN' was left blank or provided.
`tThe name 'localhost' will be used for a self signed certificate.`n`r
`t=====================================================================`n`r" -WarningAction Inquire
    }


<############### START #################>

LogWrite "`n`r`t====================================================================="
LogWrite "`tHTTPS Configurator for same computer SSL access"
LogWrite ($str0 = ("`t$version, $dateTime"))
    if
      ($domainName -eq $NULL) { LogWrite ($str1 = "`n`r`tComputer name = "+$computerName) }
    elseif 
      ($domainName -ne $NULL) { LogWrite ($str2 = "`n`r`tFQN = "+$FQN) }

LogWrite ($str3 = "`tLocalName = "+$Local)   
LogWrite "`t====================================================================="


<################ Certificate Creation Section #################>

#Remove previously created cert if it exists in each of the cert folders
$WriteFlag = $false
if($useFQN)
    {
        if($domainName -ne $NULL)
          {
            $status0 = Get-ChildItem -Path cert:\LocalMachine\My -DnsName $FQN | Remove-Item
            LogWrite ($str0 = "status0 = "+$status0)
          }
        else   
          {
            $status0 = Get-ChildItem -Path cert:\LocalMachine\My -DnsName $computerName | Remove-Item
            LogWrite ($str0 = "status0 = "+$status0)
          }

        if($domainName -ne $NULL)
          {
            $status1 = Get-ChildItem -Path cert:\LocalMachine\Root -DnsName $FQN | Remove-Item
            LogWrite ($str1 = "status1 = "+$status1)
          }
        else   
          {
            $status1 = Get-ChildItem -Path cert:\LocalMachine\Root -DnsName $computerName | Remove-Item 
            LogWrite ($str1 = "status1 = "+$status1)
          }
    }
  else
    {

        # Remove localhost entries from cert store
        $status0 = Get-ChildItem -Path cert:\LocalMachine\My -DnsName $Local | Remove-Item
        LogWrite ($str0 = "status0 = "+$status0)

        $status1 = Get-ChildItem -Path cert:\LocalMachine\Root -DnsName $Local | Remove-Item
        LogWrite ($str1 = "status1 = "+$status1)
    }


if($useFQN)
    {
        # create the ssl certificate with computer name (xyz) or FQN (.domainName.com)
        if($domainName -ne $null) 
           { # use computername
            $newCert = New-SelfSignedCertificate -DnsName $FQN -FriendlyName $computerName -CertStoreLocation cert:\LocalMachine\My 
            LogWrite ($str0 = "newCert = "+$newCert)
           }
         else
           { # use FQN
            $newCert = New-SelfSignedCertificate -DnsName $computerName -FriendlyName $computerName -CertStoreLocation cert:\LocalMachine\My 
            LogWrite ($str0 = "newCert = "+$newCert)
           }
    }
  else
    {
        # create the ssl certificate with the computer name "localhost" 
        $newCert = New-SelfSignedCertificate -DnsName $Local -FriendlyName $Local -CertStoreLocation cert:\LocalMachine\My
        LogWrite ($str0 = "newCert = "+$newCert)
    }

#Obtain the cert just created
$SourceStoreScope = 'LocalMachine' # Local Computer
LogWrite ($str1 = "SourceStoreScope = "+$SourceStoreScope)

$SourceStorename = 'My'            # named Personal in MMC Certificate add-in
LogWrite ($str2 = "SourceStoreName = "+$SourceStorename)
 
$SourceStore = New-Object  -TypeName System.Security.Cryptography.X509Certificates.X509Store  -ArgumentList $SourceStorename, $SourceStoreScope
LogWrite ($str3 = "SourceStore = "+$SourceStore)

$SourceStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
LogWrite ("SourceStore.Open Successful")

if($useFQN)
    {
        $cert = $SourceStore.Certificates | Where-Object  -FilterScript { $_.subject -like "*$computerName*" }
        LogWrite ($str0 = "cert = "+$cert)
    }
    else
    {
        $cert = $SourceStore.Certificates | Where-Object  -FilterScript { $_.subject -like "*$Local*" }
        LogWrite ($str0 = "cert = "+$cert)
    }

#Copy created cert in \My folder to \Root 
$DestStoreScope = 'LocalMachine'
LogWrite ($str1="DestStoreScope = "+$DestStoreScope)

$DestStoreName = 'Root'            # named Trusted Root... in MMC Certificate add-in
LogWrite ($str2="DestStoreName = "+$DestStoreName)
 
$DestStore = New-Object  -TypeName System.Security.Cryptography.X509Certificates.X509Store  -ArgumentList $DestStoreName, $DestStoreScope
LogWrite ($str3="DestStore = "+$DestStore)

$DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
LogWrite ($str4="DestStore.Open Successful")

$DestStore.Add($cert)              #copy cert from \My folder to \Root 
LogWrite ($str5="DestStore.Add Successful")

# Closed open objects 
$SourceStore.Close()
$DestStore.Close()

<############ WEB SITE SECTION #############>

<# obtain web binding object for default web site. Most demos default to this built in web site #>
$status2 = Get-WebBinding -Name $webSiteName   #if this web site not used and a different web site is created then this needs to be changed to that name
LogWrite ($str0="status2 = "+$status2)

$status3 = Remove-WebBinding -Name $webSiteName -IPAddress "*" -Port 443 -Protocol https -ErrorAction SilentlyContinue -ErrorVariable $err #removes binding if it exists NOT web site
LogWrite ($str1="status3 = "+$status3)

$status4 = New-WebBinding -Name $webSiteName -IPAddress "*" -Port 443 -Protocol https -ErrorVariable $err0 #creates new binding for HTTPS
LogWrite ($str2="status4 = "+$status4)

$status5 = Remove-Item -Path IIS:\SslBindings\0.0.0.0!443 -Force -ErrorAction SilentlyContinue -ErrorVariable $err1 #remove and existing https cert file item
LogWrite ($str3="status5 = "+$status5)

<#
Bind the certificate to the default website's https binding object just created

If the domain name is null then use only the computer name 
#>

if($useFQN)
    {
        if($domainName -eq $null)
          {
            $status6 = Get-ChildItem cert:\LocalMachine\My | where { $_.Subject -match "CN\=$computerName" } | select -First 1 | New-Item IIS:\SslBindings\0.0.0.0!443 -Force
            LogWrite ($str4="status6 = "+$status6)
          }
        else 
          {
            $status6 = Get-ChildItem cert:\LocalMachine\My | where { $_.Subject -match "CN\=$FQN" } | select -First 1 | New-Item IIS:\SslBindings\0.0.0.0!443 -Force
            LogWrite ($str4="status6 = "+$status6)  
          }
    }
  else
    {
        # only localhost is used for computer name
        $status6 = Get-ChildItem cert:\LocalMachine\My | where-object { $_.Subject -match "CN\=$Local" } | select -First 1 | New-Item IIS:\SslBindings\0.0.0.0!443 -Force
        LogWrite ($str4="status6 = "+$status6)
    }

$WriteFlag = $true
LogWrite ($str0="`n`r`tSelf Signed Certificate created and bound to the -> "+$webSiteName)
LogWrite
    if ( $NULL -eq $err0 -and $NULL -eq $err1) 
      { LogWrite "`tSuccess!"
        LogWrite
        LogWrite "`tUse HTTPS://localhost/<tenant name> to access demo web site."  
      }
    elseif ($Null -ne $err0 -or $NULL -ne $err1)
      {
        LogWrite ($str0="`tError in creating HTTPS Binding!"+$err0) | LogWrite ($str1="Error in adding SSL Cert to Binding"+$err1)
      }
LogWrite "`t=====================================================================`n`r"

pause