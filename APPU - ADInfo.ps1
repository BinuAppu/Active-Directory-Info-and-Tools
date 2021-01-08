<#
Update - Script will support Fine Grain Password policy
Update - Jan - 05, 2020
Created - 5/18/2017
Author - Binu Balan
#>

[console]::ForegroundColor = "White"
[console]::BackgroundColor = "Black"
cls
$host.ui.RawUI.WindowTitle = “APPU - Active Directory Info V 1.0”
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " "
Write-host "                 _    ____  ____  _   _ "
Write-host "                / \  |  _ \|  _ \| | | |"
Write-host "               / _ \ | |_) | |_) | | | |"
Write-host "              / ___ \|  __/|  __/| |_| |"
Write-host "             /_/   \_\_|   |_|    \___/ "
Write-Host " " 
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " " 
Write-host "	           .__." -ForegroundColor Green
Write-host "                   (oo)____" -ForegroundColor Green
Write-host "                   (__)    )\" -ForegroundColor Green
Write-host "                      ll--ll '" -ForegroundColor Green
Write-Host "               SCRIPT BY BINU BALAN               " -ForegroundColor DarkRed -BackgroundColor White 
Write-Host "<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>" -ForegroundColor Cyan
Write-Host ""
Write-Host "My other Scripts : http://goo.gl/CrUsnW" -ForegroundColor DarkCyan
Write-Host ""
Write-Host " _                                                     _" -ForegroundColor DarkRed
Write-host "|                                                       |" -ForegroundColor DarkRed                                                
Write-Host "|   This Script is created and Desgined by Binu Balan.  |" -ForegroundColor DarkRed
Write-Host "|   Do not modify this script which could lead to       |" -ForegroundColor DarkRed
Write-Host "|   un-expected results. Hash thumprint will be shared  |" -ForegroundColor DarkRed
Write-Host "|   while the Script is being shared to you. Validate   |" -ForegroundColor DarkRed
Write-Host "|   this to make sure you are running Genuine !!        |" -ForegroundColor DarkRed
Write-Host "|_                                                     _|" -ForegroundColor DarkRed            

#Start-Sleep -Seconds 3

[console]::ForegroundColor = "White"
[console]::BackgroundColor = "Black"

$ErrorActionPreference = 'SilentlyContinue'
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.buffersize
$newsize.height = 3000
$newsize.width = 100
$pswindow.buffersize = $newsize
$newsize = $pswindow.windowsize
$newsize.height = 50
$newsize.width = 100
$pswindow.windowsize = $newsize



Function SearchUser {
$search = New-Object DirectoryServices.DirectorySearcher([adsi]"") 
$Search.filter = “(&(objectCategory=Person)(objectClass=user)(|(mail=$UserQuery)(employeeid=$UserQuery)))”
$objUsers = $search.FindAll()
$i = 0
ForEach ($objUser in $objUsers) {
$i = $i + 1
}

[int32]$ResultCount = $i

if ($ResultCount -eq $null -or $ResultCount -eq 0) {
Write-Host "Found 0 objects !!" -ForegroundColor Yellow
NewSearch 
} Else {
Write-Host "Found Objects $i " -ForegroundColor Green
}


    ForEach ($objUser in $objUsers) {
        $GetID = ""
        $objLdap = $objUser.GetDirectoryEntry()
        $Info = $objLdap.Path
        $split = $Info.Split(":")
        $Info2 = "LDAP:" + $split[1]
        $Query = [ADSI]"$Info2"

        $GetUAC = $query.get("UserAccountControl")
        $GetDisplayName = $query.get("DisplayName")
        $GetSAM = $query.get("saMAccountName")
        $GetEmpID = $Query.get("employeeID")
        $GetLoc = $query.get('physicalDeliveryOfficeName')
        $GetLastLogon = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("lastLogon"))) 
        $getpwdlastset = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("pwdLastSet")))
        $GetCreation = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("WhenCreated")))
        $GetExpiration = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("AccountExpirationDate")))
        $GetLDAP = $query.get('distinguishedName')
        $GetProf = $Query.get('ProfilePath')
        $GetMail = $Query.get('mail')

        $LDAPSearcherVal = $query.get("distinguishedName")
        $q = [adsisearcher]""
        $val = $q.Filter="distinguishedName=$LDAPSearcherVal"
        $val = $q.PropertiesToLoad.Add('msDS-UserPasswordExpiryTimeComputed')
        $expirationdate = ($q.findone().properties).'msds-userpasswordexpirytimecomputed'
        $value=[datetime]::FromFileTime([string]$expirationdate)
        $diff = New-TimeSpan -Start (get-date) -End $value
        # $diff.Days
        $GetpwdExpDays = $diff.Days
        

        # $GetpwdExpAdd = $getpwdlastset.AddDays(90)
        # $GetpwdExpdiff = New-TimeSpan -Start (get-date) -End $GetpwdExpAdd
        # $GetpwdExpDays = $GetpwdExpdiff.Days
        if($GetpwdExpDays -lt 0){
        $GetpwdStat = "Expired $GetpwdExpDays days ago"
        $pwdcolor = "Red"
        } Elseif ($GetpwdExpDays -gt 0) {
        $GetpwdStat = "Will Expire in $GetpwdExpDays days"
        $pwdcolor = "Green"
        }
        if($GetUAC -eq 66048 -or $GetUAC -eq 65536 -or $GetUAC -eq 66050 -or $GetUAC -eq 66080){
        $GetpwdStat = "Never Expires"
        $pwdcolor = "Yellow"
        }
        $GetCreation = $Query.get("WhenCreated")
        $GetSIP = $Query.get("msRTCSIP-PrimaryUserAddress")
        $GetSIPLocFinder = $Query.get("msRTCSIP-DeploymentLocator")
        if ($GetSIPLocFinder -eq "SRV:") {
        $GetSIPLoc = "On-Prem [$GetSIPLocFinder]"
        $Siploccolor = "Green"
        } elseif ($GetSIPLocFinder -eq "sipfed.online.lync.com") {
        $GetSIPLoc = "Cloud [$GetSIPLocFinder]"
        $Siploccolor = "Yellow"
        } else {
        $GetSIPLoc = $GetSIPLocFinder
        $Siploccolor = "Red"
        }

        $GetmgrVal = $Query.Get("Manager")
        $GetMgrSplit = $GetmgrVal -split ","
        $GetMgrSplit1 = $GetMgrSplit[0] -split "="
        $GetMgrName = $GetMgrSplit1[1]

        $GetLockVal = ""
        $LckStat = ""
        $LckStat = $Query.("IsAccountLocked")
        if ($LckStat) {
        $GetLockVal = "Locked"
        $LockColor = "Red"
        } Else {
        $GetLockVal = "Not Locked"
        $LockColor = "Green"
        }
        
        $GetDisabVal = ""
        $DisabStat = ""
        $DisabStat = $Query.("AccountDisabled")
        if ($DisabStat) {
        $DisabStat = "Disabled"
        $DisabColor = "Red"
        } Else {
        $DisabStat = "Active"
        $DisabColor = "Green"
        }
        
        $GetHomeMDB = $Query.get("homeMDB")
        $splithomemdb = $GetHomeMDB -split ","
        $GetHomeMDBName = $splithomemdb -split "="
        $GetMailboxCreation = $Query.get("msExchWhenMailboxCreated")
        $GetMailboxLocVal = $objUser.properties.item("msExchRecipientTypeDetails")
        if($GetMailboxLocVal -eq 1){
        $GetMailboxType = "On-Prem" 
        $Mbxtypecolor = "Green"
        } Elseif ($GetMailboxLocVal -eq 2147483648) {
        $GetMailboxType = "Remote Mailbox"
        $Mbxtypecolor = "Yellow"
        } Else {
        $GetMailboxType = "Unknown"
        $Mbxtypecolor = "Red"
        }

        Write-Host "================================================================"
        Write-Host " "
        Write-host "	           .__." -ForegroundColor Green
        Write-host "                   (oo)____" -ForegroundColor Green
        Write-host "                   (__)    )\" -ForegroundColor Green
        Write-host "                      ll--ll '" -ForegroundColor Green
        Write-Host " "
        Write-Host "================================================================"
        Write-Host "Search Results for - " -NoNewline -BackgroundColor White -ForegroundColor Black
        Write-Host $GetDisplayName -ForegroundColor Black -BackgroundColor White
        Write-Host "================================================================"
        Write-Host " Display Name         : "$GetDisplayName
        Write-Host " Login ID             : "$GetSAM
        Write-Host " Employee ID          : "$GetEmpID
        Write-Host " Reporting Manager    : "$GetMgrName
        Write-Host " Office Location      : "$GetLoc
        Write-Host " Password Last set    : "$getpwdlastset
        Write-Host " Password Expires     :  " -NoNewline
        Write-Host $GetpwdStat -ForegroundColor $pwdcolor
        Write-Host " Account Locked       :  " -NoNewline
        Write-Host $GetLockVal -ForegroundColor $LockColor
        Write-Host " Account ActiveStat   :  " -NoNewline
        Write-Host $DisabStat -ForegroundColor $DisabColor
        Write-Host " Creation Date        : "$GetCreation
        Write-Host " Account Expires On   : "$GetExpiration
        Write-Host " Last Login           : "$GetLastLogon
        Write-Host " SIP ID               : "$GetSIP
        Write-Host " SIP Location         :  " -NoNewline
        Write-Host $GetSIPLoc -ForegroundColor $Siploccolor
        Write-Host " Mail Address         : "$GetMail
        Write-Host " Mailbox Database     : "$GetHomeMDBName[1]
        Write-Host " Mailbox Creation     : "$GetMailboxCreation
        Write-Host " Mailbox Type         :  " -NoNewline
        Write-Host $GetMailboxType -ForegroundColor $Mbxtypecolor
        Write-Host " Profile Path         : "$GetProf
        Write-Host " LDAP Path            : "$GetLDAP



        Write-Host " "
        Write-Host "================================================================"
        Write-Host " "
        Write-Host "N - New Query" -ForegroundColor Black -BackgroundColor White -NoNewline
        Write-Host " / " -NoNewline
        Write-Host "E - Exit" -ForegroundColor Red -BackgroundColor Yellow
        $option = Read-Host "Enter Option "
        if ($option -eq "N" -or $option -eq $null -or $option -eq ""){
        NewSearch
        } Else {
        SayThanks
        }

    }



}

Function NewSearch {
Write-Host ""
$UserQuery = Read-Host "Enter Employee ID / Email ID to Search "
$Search = New-Object System.DirectoryServices.DirectorySearcher($ADsPath)
if ($UserQuery -ne $null){
Write-Host "Searching User...."
SearchUser
} else {
Write-Host "Enter Employee ID / Email ID to Search !!"
}

}

Function SayThanks {
Write-Host "Thank you for using this Script !!" -ForegroundColor Yellow
Start-Sleep -Seconds 3
Exit
}

NewSearch
#End of Script