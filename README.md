# setup-ssl
Powershell script to setup and configure all the settings to enable HTTPS connections to websites named "localhost" on a local PC running IIS.
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

