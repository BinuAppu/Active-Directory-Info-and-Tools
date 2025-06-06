<#
    Write-Host " "
    Write-Host " "                                              
    Write-Host "       __      ______   ______   _____  _____ " -ForegroundColor DarkBlue
    Write-Host "      /  \    |_   __ \|_   __ \|_   _||_   _|" -ForegroundColor DarkCyan
    Write-Host "     / /\ \     | |__) | | |__) | | |    | |  " -ForegroundColor DarkGray
    Write-Host "    / ____ \    |  ___/  |  ___/  | |    | |  " -ForegroundColor DarkGreen
    Write-Host "  _/ /    \ \_ _| |_    _| |_     | |____| |  " -ForegroundColor DarkMagenta
    Write-Host " |____|  |____|_____|  |_____|     \.____./   " -ForegroundColor DarkYellow
    Write-Host " "  
    Write-Host " "
    Script : Created by Binu Balan
    Digitally Signed : Binu Balan
    Created On : 8/8/2023
    Version - 1.0 - 8/8/2023
    Version - 1.1 - 8/22/2023
    Version - 1.2 - 9/12/2023
    Version - 1.3 - 9/29/2023
    Version - 1.4 - 12/30/2024
    Notes:
        1.0 Combined AD Info and
        1.1 Added Temp file removal and Random Password Generator
        1.2 * BETA * SSL Certificate Check on remote port
        1.2 Full Version released Added SSL/TLS Scan.
        1.3 * BETA * LAPS, User Password Expiration date, added Base64 Encoding/Decoding, Encryption and Decryption.
        1.4 Introduced HASH functionality
#>

$version = "1.4"

# Progress Bar color
$host.privatedata.ProgressForegroundColor = "darkgreen";
$host.privatedata.ProgressBackgroundColor = "Black";

#Console Settings
[console]::ForegroundColor = "White"
[console]::BackgroundColor = "Black"
Clear-Host
$host.ui.RawUI.WindowTitle = "APPU - All In One - $version"
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

function GetHASHofFile {
    Clear-Host
    loadlogo
    Write-Host " "
    Write-Host " [ HASH GENERATOR FOR A FILE ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-Host " "
    # add option to perform query for multiple files in a given directory and sigle file
    Write-Host " "
    Write-Host " 1. Perfrom Query for Single File. "
    Write-Host " 2. Query for multiple files under specific folder. "
    Write-Host " "
    $ask = Read-Host " Prompt > "
    # include hash type selection
    $hashAsk = Read-Host " Enter the Hash type [MD5, SHA1, SHA256, SHA512] "
    if ($ask -eq 1) {
        $file = Read-Host " Enter the file path "
        $hash = Get-FileHash -Path $file -Algorithm $hashAsk
        Write-Host " "
        Write-Host " { " -ForegroundColor Gray
        Write-Host "   $file" -ForegroundColor Yellow
        Write-Host " } " -ForegroundColor Gray
        Write-Host " { " -ForegroundColor Gray
        Write-Host "     " $hash.Hash
        Write-Host " } " -ForegroundColor Gray
    }
    elseif ($ask -eq 2) {
        $folder = Read-Host " Enter the folder path "
        $files = Get-ChildItem -Path $folder
        foreach ($file in $files) {
            $hash = Get-FileHash -Path $file.FullName -Algorithm $hashAsk
            Write-Host "HASH : "$hash.Hash " File: " $hash.Path 
        }
    }
    else {
        Write-Host " "
        Write-Host " [Error] " -ForegroundColor Red -NoNewline
        Write-Host "Wrong option selected. Redirecting to Main menu in 2 seconds !!" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        Loading
    }

    Write-host " "
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor DarkBlue
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor DarkBlue
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        GetHASHofFile
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        GetHASHofFile
    }

}

function EncryptDecryptString {

    Clear-Host
    #Encoding and Decoding base64
    loadlogo
       
    Write-Host " "
    Write-Host " 1. Encrypt a String to AES and convert to Base64. "
    Write-Host " 2. Decrypt a Base64 AES Encryption to String. "
    Write-Host " "
    $ask = Read-Host " Prompt > "

    if ($ask -eq 1) {
       
        # Define your message to encrypt
        $plaintext = Read-Host " Enter the String to Encrypt "

        # Convert the message to bytes
        $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)

        # Define the password (make sure to store it securely)
        # $password = Read-Host " Enter password for Encryption " -AsSecureString
        $MySecurePassword = read-host -assecurestring " Enter password "
        $pPassPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($MySecurePassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pPassPointer)
        # Imported: free memory
        # [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
        # write-host "PASS:" $password

        # Create a key and initialization vector (IV) from the password
        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes("SaltValue"), 1000).GetBytes(32)
        $iv = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes("SaltValue"), 1000).GetBytes(16)

        # Create an AES encryption object
        $aes = [System.Security.Cryptography.AesManaged]::new()
        $aes.Key = $key
        $aes.IV = $iv

        # Create a memory stream to write the encrypted data
        $memoryStream = [System.IO.MemoryStream]::new()
        $encryptor = $aes.CreateEncryptor()
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        # Write the encrypted data to the stream
        $cryptoStream.Write($plaintextBytes, 0, $plaintextBytes.Length)
        $cryptoStream.FlushFinalBlock()

        # Get the encrypted bytes
        $encryptedBytes = $memoryStream.ToArray()

        # Convert the encrypted bytes to base64
        $base64Encrypted = [System.Convert]::ToBase64String($encryptedBytes)

        Write-Host " Base64 Encrypted Message : " -NoNewline -ForegroundColor Yellow
        Write-Host $base64Encrypted -ForegroundColor Green

    }
    elseif ($ask -eq 2) {
        # The base64-encoded encrypted message
        $base64EncryptedMessage = Read-Host " Enter the encrypted Base64 data for Decryption "

        # Convert the base64-encoded message back to bytes
        $encryptedBytes = [System.Convert]::FromBase64String($base64EncryptedMessage)

        # Define the password (must match the one used for encryption)
        # $password = Read-Host " Enter password for Encryption " -AsSecureString
        $MySecurePassword = read-host -assecurestring " Enter password "
        $pPassPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($MySecurePassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pPassPointer)
        # Imported: free memory
        # [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
        # write-host "PASS:" $password

        # Create a key and initialization vector (IV) from the password
        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes("SaltValue"), 1000).GetBytes(32)
        $iv = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes("SaltValue"), 1000).GetBytes(16)

        # Create an AES decryption object
        $aes = [System.Security.Cryptography.AesManaged]::new()
        $aes.Key = $key
        $aes.IV = $iv

        # Create a memory stream to read the encrypted data
        $memoryStream = [System.IO.MemoryStream]::new($encryptedBytes)
        $decryptor = $aes.CreateDecryptor()
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # Create a buffer to hold the decrypted data
        $buffer = [byte[]]::new($encryptedBytes.Length)

        # Read the decrypted data from the stream
        $bytesRead = $cryptoStream.Read($buffer, 0, $buffer.Length)

        # Convert the decrypted bytes to text
        $decryptedText = ""
        $decryptedText = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
        if ($decryptedText -eq "") {
            Write-Host "[ ERROR Decrypting ]" -ForegroundColor Red -BackgroundColor Yellow -NoNewline
            Write-Host " It seems your password didnt work for decryption :-( " -ForegroundColor Red
        }
        else {
            Write-Host " Decrypted Message : " -ForegroundColor Yellow -NoNewline
            Write-Host $decryptedText -ForegroundColor Green
        }
    }
    else {
        Write-Host " "
        Write-Host " [Error] " -ForegroundColor Red -NoNewline
        Write-Host "Wrong option selected. Redirecting to Main menu in 2 seconds !!" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        Loading
    }

    Write-host " "
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor DarkBlue
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor DarkBlue
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        EncryptDecryptString
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        EncryptDecryptString
    }

}



function converttoandfrombase64 {
    Clear-Host
    #Encoding and Decoding base64
    loadlogo
       
    Write-Host " "
    Write-Host " 1. Encode a String to Base64"
    Write-Host " 2. Decode a String from Base64"
    Write-Host " "
    $ask = Read-Host " Prompt > "

    if ($ask -eq 1) {
        Write-Host " Enter a String below to convert into Base64" -ForegroundColor Green
        $encode = Read-Host " Input String "
        $plaintexttoBytes = [System.Text.Encoding]::UTF8.GetBytes($encode)
        $base64 = [System.Convert]::ToBase64String($plaintexttoBytes)
        Write-Host " "
        Write-Host " { " -ForegroundColor Gray
        Write-Host "            " $base64
        Write-Host " } " -ForegroundColor Gray
    }
    elseif ($ask -eq 2) {
        Write-Host " Enter the Base64 data below to convert to String" -ForegroundColor Green
        $decode = Read-Host " Input Base64 "
        $frombase64 = [System.Convert]::FromBase64String($decode)
        $Converttotext = [System.Text.Encoding]::UTF8.GetString($frombase64)
        Write-Host " "
        Write-Host " { " -ForegroundColor Gray
        Write-Host "            " $Converttotext
        Write-Host " } " -ForegroundColor Gray
    }
    else {
        Write-Host " "
        Write-Host " [Error] " -ForegroundColor Red -NoNewline
        Write-Host "Wrong option selected. Redirecting to Main menu in 2 seconds !!" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        Loading
    }
   

    Write-host " "
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor DarkBlue
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor DarkBlue
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        converttoandfrombase64
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        converttoandfrombase64
    }
}


function sslscan-clean {
    Clear-Host
    sslscan
}

function sslscan {
   
    loadlogo
    Write-host " "
    Write-Host " [ SSL VERSION SCAN ON A REMOTE/LOCAL PORT ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "

    $remoteComputer = Read-Host " Enter the HostName / IP "
    $port = Read-Host " Enter the Port Number "
    Write-host " "
    $allcipher = "Ssl2", "Ssl3", "Tls", "Tls11", "Tls12", "Tls13"
    Write-Host " { SSL / TLS Version Scanner }" -ForegroundColor Green
    Write-Host " ============================= " -ForegroundColor White
    forEach ($tls in $allcipher) {
        $tcpclient = New-Object System.Net.Sockets.TcpClient
        $tcpclient.Connect($remoteComputer, $port)
   
        $sslStream = New-Object System.Net.Security.SslStream($tcpclient.GetStream(), $false, { $true })
        try {
            $sslStream.AuthenticateAsClient($remoteComputer, $null, [System.Security.Authentication.SslProtocols]::$tls, $false)
        }
        catch {
            #Write-Host " { Error } " -ForegroundColor Red -NoNewline
            #Write-host "[ $($_.Exception.Message) ]" -ForegroundColor Yellow
       
        }
   
        $Cert = $sslStream.RemoteCertificate
   
   
        if ($cert -ne $null) {
            Write-Host " [Success] " -ForegroundColor Green -NoNewline
            Write-Host "$tls "

        }
        else {

            Write-Host " [Failed]  " -ForegroundColor Red -NoNewline
            Write-Host "$tls "
        }
   
        $sslStream.Dispose()
        $tcpClient.Close()
    }
    Write-host " "
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        sslscan-clean
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        sslscan-clean
    }

}


function ssl-clean {
    Clear-Host
    Check-SSL
}

function loadlogo {
    $col = "Yellow", "Gray", "White", "Yellow", "Blue", "Green"

    Write-Host " "
    Write-Host " "                                              
    $colorval = Get-Random $col
    Write-Host "       __      ______   ______   _____  _____ " -ForegroundColor $colorval
    $colorval = Get-Random $col
    Write-Host "      /  \    |_   __ \|_   __ \|_   _||_   _|" -ForegroundColor $colorval
    $colorval = Get-Random $col
    Write-Host "     / /\ \     | |__) | | |__) | | |    | |  " -ForegroundColor $colorval
    $colorval = Get-Random $col
    Write-Host "    / ____ \    |  ___/  |  ___/  | |    | |  " -ForegroundColor $colorval
    $colorval = Get-Random $col
    Write-Host "  _/ /    \ \_ _| |_    _| |_     | |____| |  " -ForegroundColor $colorval
    $colorval = Get-Random $col
    Write-Host " |____|  |____|_____|  |_____|     \.____./   " -ForegroundColor $colorval
    Write-Host " "  
    Write-Host " "


    <#

        Write-Host " "
        Write-Host "  _____                        _______            " -ForegroundColor $colorval      
        $colorval = Get-Random $col
        Write-Host " / ____|                      |__   __|                           " -ForegroundColor $colorval
        $colorval = Get-Random $col
        Write-Host " | (___   ___ _ ____   _____ _ __| | ___  __ _ _ __ ___             " -ForegroundColor $colorval
        $colorval = Get-Random $col
        Write-Host " \___ \ / _ \ '__ \ \ / / _ \ '__| |/ _ \/  _` | '_ ` _   \         " -ForegroundColor $colorval
        $colorval = Get-Random $col
        Write-Host " ____) |  __/  |   \ V /  __/ |  | |  __/ (_| | | | | | |       " -ForegroundColor $colorval
        $colorval = Get-Random $col
        Write-Host " |_____/ \___|_|    \_/ \___|_|  |_|\___|\__,_|_| |_| |_|       " -ForegroundColor $colorval
        $colorval = Get-Random $col
        Write-Host "                                                       " -ForegroundColor $colorval
        Write-Host "                                                       " -ForegroundColor $colorval

    #>

}  

function Check-SSL {

    loadlogo
    Write-host " "
    Write-Host " [ CHECKING SSL CERTIFICATE ON REMOTE PORT ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "

    $remoteComputer = Read-Host " Enter the HostName / IP "
    $port = Read-Host " Enter the Port Number "
    Write-Host " Which TLS/SSL you would like to try to connect to remote endpoint"
    Write-Host "
    1. None [OS Default]
    2. Ssl2
    3. Ssl3
    4. Tls
    5. Tls11
    6. Tls12
    7. Tls13"
    $tlsask = Read-host " Prompt > "
    $tls = switch ($tlsask) {
        1 { 'None' }
        2 { 'Ssl2' }
        3 { 'Ssl3' }
        4 { 'Tls' }
        5 { 'Tls11' }
        6 { 'Tls12' }
        7 { 'Tls13' }
        Default { 'None' }
    }

    $tcpclient = New-Object System.Net.Sockets.TcpClient
    $tcpclient.Connect($remoteComputer, $port)
   
    $sslStream = New-Object System.Net.Security.SslStream($tcpclient.GetStream(), $false, { $true })
    try {
        $sslStream.AuthenticateAsClient($remoteComputer, $null, [System.Security.Authentication.SslProtocols]::$tls, $false)
    }
    catch {
        Write-Host " { Error } " -ForegroundColor Red -NoNewline
        Write-host "[ $($_.Exception.Message) ]" -ForegroundColor Yellow
    }
   
    $Cert = $sslStream.RemoteCertificate
   
   
    if ($cert -ne $null) {
        Write-Host " "
        Write-Host " Certificate Information " -ForegroundColor Green
        Write-Host " ======================= " -ForegroundColor Green
        Write-Host " "
        Write-Host " Issuer          : " -ForegroundColor Yellow -NoNewline
        Write-Host "$($cert.Issuer)"
        Write-Host " Thumbprint      : " -ForegroundColor Yellow -NoNewline
        Write-Host "$($cert.GetCertHashString())"
        Write-Host " Effective Date  : " -ForegroundColor Yellow -NoNewline
        Write-Host "$($cert.GetEffectiveDateString())"
        Write-Host " Expiration Date : " -ForegroundColor Yellow -NoNewline
        Write-Host "$($cert.GetExpirationDateString())"
        $protocolInfo = $sslStream.SslProtocol
        Write-Host " Protocol        : " -ForegroundColor Yellow -NoNewline
        Write-host $protocolInfo
        Write-Host " Subject         : " -ForegroundColor Yellow -NoNewline
        Write-host "$($cert.Subject)"
        Write-Host "  " -ForegroundColor Green
    }
    else {
        Write-Host " { Failed to Connect or Cipher [ $tls ] is not Supported. } " -ForegroundColor Gray
        Write-Host "  " -ForegroundColor Green
    }
   
    $sslStream.Dispose()
    $tcpClient.Close()
   
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        ssl-clean
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        ssl-clean
    }

}

function GeneratePwd ($length) {

    $UAlpha = "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
    $LAlpha = "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"
    $Num = "1", "2", "3", "4", "5", "6", "7", "8", "9", "0"
    $Special = "!", "$", "%", "&", "(", ")", "*", "+", "-", "/", ":", ";", "<", "=", ">", "?", "@", "[", "\", "]", "^", "_", "{", "}", "~"

    $passlenght = 10..16
    # $ReqPassLenght = Get-Random $passlenght
    $ReqPassLenght = $length

    # Write-Host "$ReqPassLenght"

    $x = 0
    do {


        $U = $null
        if ($x -ne $ReqPassLenght) {
            $Us = $UAlpha | Sort-Object { Get-Random } -Unique        
            $U = Get-Random $Us -Minimum $passlenght
            [array]$Pass1 = $Pass1 + $U
            $x = $x + 1
        }



        $L = $null
        if ($x -ne $ReqPassLenght) {
            $Ls = $LAlpha | Sort-Object { Get-Random } -Unique
            $L = Get-Random $Ls -Minimum $passlenght
            [array]$Pass2 = $Pass2 + $L
            $x = $x + 1
        }



        $N = $null
        if ($x -ne $ReqPassLenght) {
            $Ns = $Num | Sort-Object { Get-Random } -Unique
            $N = Get-Random $Ns -Minimum $passlenght
            [array]$Pass3 = $Pass3 + $N
            $x = $x + 1
        }


        $S = $null
        if ($x -ne $ReqPassLenght) {
            $Ss = $Special | Sort-Object { Get-Random } -Unique
            $S = Get-Random $Ss -Minimum $passlenght
            [array]$Pass4 = $Pass4 + $S
            $x = $x + 1
        }


    }
    until ($x -eq $ReqPassLenght)

    $PassOut = $Pass1 + $Pass2 + $Pass3 + $Pass4

    [string]$Shuffle = $PassOut | Sort-Object { Get-Random } -Unique
    # Write-Host "AppuPass = $PassOut"
    $JoiningPwd = $Shuffle -split " "

    ForEach ($Pwd in $JoiningPwd) {
        $OutputPassword = $OutputPassword + $Pwd
    }


    Write-Host " Here is your Random Password - " -NoNewline
    Write-Host "$OutputPassword" -ForegroundColor Green -BackgroundColor Black

}

function RandomPass () {
    Clear-Host
   
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING RANDOM PASSWORD GENERATION ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "

    $i = 1
    $Length = Read-Host (" Enter the password lenght ")
    Write-Host " ================================================================================ "
    Write-host " I will help you generate 10 Random password, you may select which you wish !!" -ForegroundColor Blue
    Write-Host " ================================================================================ "
    do {
        GeneratePwd $Length
        $i++
    } until ($i -eq 11)
    Write-Host " ================================================================================ "
    Write-Host " "

    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
           
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        RandomPass
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        RandomPass
    }
}

function TempFileDeletion {
    Clear-Host
   
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING TEMP FILE / FOLDER DELETION ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # No Action
    }
    else {
        Write-Host (" [Warning] ") -nonewline -foregroundcolor DarkYellow
        Write-Host "You are not running this Shell as { ADMIN }. Not all Temp files will be deleted !!"
        Write-Host " "
    }
   
    Start-Sleep -Seconds 2
    Write-Host " "
    Write-Host "Welcome : "$env:USERNAME
    Write-Host "======================"
    Write-Host " "
    Sleep -s 2
    Write-host "Please wait... Deleting Temp files" -ForegroundColor Yellow
    Write-Host " "
    $ErrorActionPreference = "SilentlyContinue"
    Sleep -s 2
    Write-Host "Deleting User Temp Files....     " -NoNewline
    Remove-Item -Path $env:TEMP -Recurse -Force
    Sleep -s 2
    Write-Host "[   OK   ]" -ForegroundColor Green
    $Temp = $env:SystemRoot + "\Temp"
    Write-Host "Deleting Windows Temp Files....  " -NoNewline
    Remove-Item -Path $Temp -Recurse -Force
    Sleep -s 2
    Write-Host "[   OK   ]" -ForegroundColor Green
    $ErrorActionPreference = "Continue"
    Write-Host " "
    Write-Host "========================="
    Write-Host "End of Script, Thank you."
    Write-Host "========================="
    Sleep -s 5


    Write-Host " " -NoNewline
    Write-Host " E " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " Exit " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " "
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "E" -or $NextWhat -eq "e") {
        exit
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        exit
    }
}


function PortQuery {
    Clear-Host
   
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING TCP PORT QUERY ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "


    $Error.Clear()
    $ErrorActionPreference = "SilentlyContinue"
    Write-Host "
       1 - Individual Port Test
       2 - Test a particular Port Range
       3 - Test specific multiple ports
       4 - Perform Port Ping
       5 - Multiple IP and Port test
    " -ForegroundColor Green
    $RSM = Read-Host (" Enter the option [1,2,3,4,5]")
    if ($RSM -eq 1) {
        $IPAdd = Read-Host (" Enter the IP/Host Name Address ")
        $PortNum = Read-Host (" Enter the individual Port [443]")
        $PortChk = New-Object -TypeName System.Net.Sockets.TcpClient
        $PortChk.ReceiveTimeout = 5000
        $result = $PortChk.connect($IPAdd, $PortNum)
        $portChk.Close()
        Write-Host " "
        if ($Error -ne $Null) {
            Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Black -BackgroundColor Red -NoNewline
            Write-Host "CLOSED" -ForegroundColor Black -BackgroundColor Red
        }
        Else {
            Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Green -NoNewline
            Write-Host "OPEN" -ForegroundColor Green
        }
        $Error.Clear()
    }
    Elseif ($RSM -eq 2) {
        $IPAdd = Read-Host (" Enter the IP/Host Name Address ")
        $PortNumG = Read-Host (" Enter the Port Range [20-33]")
        $PortNumS = $PortNumG.Split("-")
        [int]$i = 0
        [int]$a = $PortNumS[0]
        [int]$z = $PortNumS[1]
        Write-Host " "
        for ($i = $a; $i -lt ($z + 1); $i++) {
            $PortNum = $i
            $Error.Clear()
            $PortChk = New-Object -TypeName System.Net.Sockets.TcpClient
            $PortChk.ReceiveTimeout = 5000
            $result = $PortChk.connect($IPAdd, $PortNum)
            $portChk.Close()
            if ($Error -ne $Null) {
                Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Black -BackgroundColor Red -NoNewline
                Write-Host "CLOSED" -ForegroundColor Black -BackgroundColor Red
            }
            Else {
                Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Green -NoNewline
                Write-Host "OPEN" -ForegroundColor Green
            }
            $Error.Clear()
        }
    }
    Elseif ($RSM -eq 3) {
        $IPAdd = Read-Host (" Enter the IP/Host Name Address ")
        $PortNumG = Read-Host (" Enter the Multiple Port Number [80,443]")
        $PortNumS = $PortNumG.Split(",")
        Write-Host " "
        foreach ($PortNum in $PortNumS) {
            $Error.Clear()
            $PortChk = New-Object -TypeName System.Net.Sockets.TcpClient
            $PortChk.ReceiveTimeout = 5000
            $result = $PortChk.connect($IPAdd, $PortNum)
            $portChk.Close()
            if ($Error -ne $Null) {
                Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Black -BackgroundColor Red -NoNewline
                Write-Host "CLOSED" -ForegroundColor Black -BackgroundColor Red
            }
            Else {
                Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Green -NoNewline
                Write-Host "OPEN" -ForegroundColor Green
            }
        }
    }
    Elseif ($RSM -eq 4) {
        $IPAdd = Read-Host (" Enter the IP/Host Name Address ")
        $PortNum = Read-Host (" Enter the Port number ")
        [int]$NumCheck = Read-Host (" Enter number of Port Check ")
        Write-Host " "
        for ($i = 1; $i -lt ($NumCheck + 1); $i++) {
            $Error.Clear()
            $PortChk = New-Object -TypeName System.Net.Sockets.TcpClient
            $PortChk.ReceiveTimeout = 5000
            $result = $PortChk.connect($IPAdd, $PortNum)
            $portChk.Close()
            Write-Host " $IPAdd : Port Ping number $i " -NoNewline
            if ($Error -ne $Null) {
                Write-Host "          [FAILED]" -ForegroundColor Black -BackgroundColor Red
            }
            Else {
                Write-Host "          [OPEN]" -ForegroundColor Green -BackgroundColor Black
            }
            $Error.Clear()
        }
    }
    Elseif ($RSM -eq 5) {
        $IPAddG = Read-Host (" Enter Multiple IP/Host Name Address [10.0.0.1,10.0.0.2]")
        $PortNumG = Read-Host (" Enter the Multiple Port Number [80,443]")
        Write-Host " "
        $IPAddS = $IPAddG.Split(",")
        $PortNumS = $PortNumG.Split(",")
        ForEach ($IPAdd in $IPAddS) {
            ForEach ($PortNum in $PortNumS) {
                $Error.Clear()
                $PortChk = New-Object -TypeName System.Net.Sockets.TcpClient
                $PortChk.ReceiveTimeout = 5000
                $result = $PortChk.connect($IPAdd, $PortNum)
                $portChk.Close()
                if ($Error -ne $Null) {
                    Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Black -BackgroundColor Red -NoNewline
                    Write-Host "CLOSED" -ForegroundColor Black -BackgroundColor Red
                }
                Else {
                    Write-Host " $IPAdd : Port $PortNum is " -ForegroundColor Green -NoNewline
                    Write-Host "OPEN" -ForegroundColor Green
                }
            }
        }
    }
    Else {
        Write-Host " "
        Write-Host " "
        Write-Warning " You have enterered wrong input value !!"
        Write-Host " Valid numbers are - 1,2,3,4,5" -ForegroundColor Green
    }
    $Error.Clear()
    $ErrorActionPreference = "Continue"
    Write-Host " "

    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        PortQuery
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        PortQuery
    }

}


# =============================================================================================================
# =============================================================================================================
# USER QUERY
# =============================================================================================================
# =============================================================================================================



function Loading {
    Clear-Host
    $ran = Get-random 1, 2, 3, 4

    if ($ran -eq 1) {

        Write-host "                ,@@@@@@@," -ForegroundColor Green
        Write-host "        ,,,.   ,@@@@@@/@@,  .oo8888o." -ForegroundColor Green
        Write-host "     ,&%%&%&&%,@@@@@/@@@@@@,8888\88/8o" -ForegroundColor Green
        Write-host "    ,%&\%&&%&&%,@@@\@@@/@@@88\88888/88" -ForegroundColor Green
        Write-host "    %&&%&%&/%&&%@@\@@/ /@@@88888\88888" -ForegroundColor Green
        Write-host "    %&&%/ %&%%&&@@\ V /@@' ` 88\8 `/88" -ForegroundColor Green
        Write-host "     &%\   /%&     |.|        \  |8" -ForegroundColor DarkCyan
        Write-host "        |o|        | |         | |" -ForegroundColor DarkCyan
        Write-host "        |.|        | |         | |" -ForegroundColor DarkCyan
        Write-host "     \\/ ._\//_/__/  ,\_//__\\/.  \_//__/_" -ForegroundColor Green
        Write-Host " "
        Write-host " Loading.... Please wait !"
        Start-Sleep -Seconds 2
        Clear-Host

    }
    elseif ($ran -eq 2) {

        Write-host "                  .88888888:." -ForegroundColor DarkGray
        Write-host "                 88888888.88888." -ForegroundColor DarkGray
        Write-host "               .8888888888888888." -ForegroundColor DarkGray
        Write-host "               888888888888888888" -ForegroundColor DarkGray
        Write-host "               88' _  88 _  '88888" -ForegroundColor DarkGray
        Write-host "               88 88 88 88  88888"
        Write-host "               88_88_::_88_:88888"
        Write-host "               88:::,::,:::::8888"
        Write-host "               88`:::::::::'`8888"
        Write-host "              .88  `::::'    8:88."
        Write-host "             8888            `8:888." -ForegroundColor DarkGray
        Write-host "           .8888'             `888888." -ForegroundColor DarkGray
        Write-host "          .8888:..  .::.  ...:'8888888:." -ForegroundColor DarkGray
        Write-host "         .8888.'     :'     `'::`88:88888" -ForegroundColor DarkGray
        Write-host "        .8888        '         `.888:8888." -ForegroundColor DarkGray
        Write-host "       888:8         .           888:88888" -ForegroundColor DarkGray
        Write-host "     .888:88        .:           888:88888:" -ForegroundColor DarkGray
        Write-host "     8888888.       ::           88:888888" -ForegroundColor DarkGray
        Write-host "     `.::.888.      ::          .88888888" -ForegroundColor DarkGray
        Write-host "    .::::::.888.    ::         :::`8888'.:."
        Write-host "   ::::::::::.888   '         .::::::::::::"
        Write-host "   ::::::::::::.8    '      .:8::::::::::::."
        Write-host "  .::::::::::::::.        .:888:::::::::::::"
        Write-host "  :::::::::::::::88:.__..:88888:::::::::::'"
        Write-host "   `'.:::::::::::88888888888.88:::::::::'"
        Write-host "           :::_: --  - -   :_::::"
        Write-Host " "
        Write-host " Loading.... Please wait !"
        Start-Sleep -Seconds 2
        Clear-Host

    }
    elseif ($ran -eq 3) {    

        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " "
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-host " ################  ################ " -ForegroundColor Blue
        Write-Host " "
        Write-host " Loading.... Please wait !"
        Start-Sleep -Seconds 2
        Clear-Host

    }
    elseif ($ran -eq 4) {


        Write-Host " "
        Write-host "                   .__." -ForegroundColor Green
        Write-host "                   (oo)____" -ForegroundColor Green
        Write-host "                   (__)    )\" -ForegroundColor Green
        Write-host "                      ll--ll '" -ForegroundColor Green
        Write-Host " "
        Write-host " Loading.... Please wait !"
        Start-Sleep -Seconds 2
        Clear-Host
    
    }
    MainMenu
}

Function GetUserIP ($GetIP) {
    $bin = [convert]::ToString($GetIP, 2).PadLeft(32, '0').ToCharArray()
    $A = [convert]::ToByte($bin[0..7] -join "", 2)
    $B = [convert]::ToByte($bin[8..15] -join "", 2)
    $C = [convert]::ToByte($bin[16..23] -join "", 2)
    $D = [convert]::ToByte($bin[24..31] -join "", 2)
    return $($A, $B, $C, $D -join ".")
}


Function SearchUser ($UserQuery) {
    $search = New-Object DirectoryServices.DirectorySearcher([adsi]"")
    $Search.filter = "(&(objectCategory=Person)(objectClass=user)(|(mail=$UserQuery)(employeeid=$UserQuery)(samaccountname=$UserQuery)))"
    $objUsers = $search.FindAll()
    $i = 0
    ForEach ($objUser in $objUsers) {
        $i = $i + 1
    }

    [int32]$ResultCount = $i

    if ($ResultCount -eq $null -or $ResultCount -eq 0) {
        Write-Host "      { " -ForegroundColor DarkYellow
        Write-Host "        Search resulted in NULL Output.... Possible cause !!" -ForegroundColor DarkYellow
        Write-Host "         { " -ForegroundColor DarkYellow
        Write-Host "            No connectivity to Active Directory " -ForegroundColor DarkYellow
        Write-Host "                 OR " -ForegroundColor Yellow
        Write-Host "            Unable to find AD Object " -NoNewline -ForegroundColor DarkYellow
        Write-Host "{ " -ForegroundColor Cyan -NoNewline
        Write-Host "$UserQuery" -NoNewline -ForegroundColor Yellow
        Write-Host " }" -ForegroundColor Cyan -NoNewline
        Write-Host "  " -ForegroundColor DarkYellow
        Write-Host "         } " -ForegroundColor DarkYellow
        Write-Host "      } " -ForegroundColor DarkYellow
        Pause
        NewSearch
    }
    Else {
        Write-Host " Got one Object { $i }" -ForegroundColor Green
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
        $GetUPN = $query.get("userPrincipalName")
        $UPNColor = "White"
        $GetLastLogon = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("lastLogon")))
        $getpwdlastset = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("pwdLastSet")))
        $GetCreation = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("WhenCreated")))
        $GetExpiration = [datetime]::FromFileTime([int64]::Parse($objUser.properties.item("AccountExpirationDate")))
        $GetLDAP = $query.get('distinguishedName')
        $GetProf = $Query.get('ProfilePath')
        $GetMail = $Query.get('mail')
       
        $dialinStatus = $Query.get('msnpallowdialin')
        $dialinIPRaw = $Query.Get('msRADIUSFramedIPAddress')
        $dialinIP = GetUserIP $dialinIPRaw
        $Dialinstatuscolor = "white"
        if ($dialinStatus -eq $null) {
            $dialinStatus = "Control access through NPS Network Policy"
            $Dialinstatuscolor = "Green"
        }

        if ($dialinStatus -eq $False) {
            $Dialinstatuscolor = "Red"
        }

        if ($dialinIP -eq $null) {
            $dialinIP = "No IP Set"
            $dialinIPColor = "Red"
        }

        $LDAPSearcherVal = $query.get("distinguishedName")
        $q = [adsisearcher]""
        $val = $q.Filter = "distinguishedName=$LDAPSearcherVal"
        $val = $q.PropertiesToLoad.Add('msDS-UserPasswordExpiryTimeComputed')
        $expirationdate = ($q.findone().properties).'msds-userpasswordexpirytimecomputed'
        $value = [datetime]::FromFileTime([string]$expirationdate)
        $diff = New-TimeSpan -Start (get-date) -End $value
        # $diff.Days
        $GetpwdExpDays = $diff.Days
           

        # $GetpwdExpAdd = $getpwdlastset.AddDays(90)
        # $GetpwdExpdiff = New-TimeSpan -Start (get-date) -End $GetpwdExpAdd
        # $GetpwdExpDays = $GetpwdExpdiff.Days
        if ($GetpwdExpDays -lt 0) {
            $GetpwdStat = "Expired $GetpwdExpDays days ago [$value]"
            $pwdcolor = "Red"
        }
        Elseif ($GetpwdExpDays -gt 1) {
            $GetpwdStat = "Expire's in $GetpwdExpDays days [$value]"
            $pwdcolor = "Green"
        }
        Elseif ($GetpwdExpDays -eq 1 -or $GetpwdExpDays -eq 0) {
            $GetpwdStat = "Expire's in $GetpwdExpDays days [$value]"
            $pwdcolor = "Yellow"
        }
        if ($GetUAC -eq 66048 -or $GetUAC -eq 65536 -or $GetUAC -eq 66050 -or $GetUAC -eq 66080) {
            $GetpwdStat = "Never Expires"
            $pwdcolor = "Yellow"
        }
        $GetCreation = $Query.get("WhenCreated")
        $GetSIP = $Query.get("msRTCSIP-PrimaryUserAddress")
        $GetSIPLocFinder = $Query.get("msRTCSIP-DeploymentLocator")
        if ($GetSIPLocFinder -eq "SRV:") {
            $GetSIPLoc = "On-Prem [$GetSIPLocFinder]"
            $Siploccolor = "Green"
        }
        elseif ($GetSIPLocFinder -eq "sipfed.online.lync.com") {
            $GetSIPLoc = "Cloud [$GetSIPLocFinder]"
            $Siploccolor = "Yellow"
        }
        else {
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
        }
        Else {
            $GetLockVal = "Not Locked"
            $LockColor = "Green"
        }
       
        $GetDisabVal = ""
        $DisabStat = ""
        $DisabStat = $Query.("AccountDisabled")
        if ($DisabStat) {
            $DisabStat = "Disabled"
            $DisabColor = "Red"
        }
        Else {
            $DisabStat = "Active"
            $DisabColor = "Green"
        }
       
        $GetHomeMDB = $Query.get("homeMDB")
        $splithomemdb = $GetHomeMDB -split ","
        $GetHomeMDBName = $splithomemdb -split "="
        $GetMailboxCreation = $Query.get("msExchWhenMailboxCreated")
        $GetMailboxLocVal = $objUser.properties.item("msExchRecipientTypeDetails")
        if ($GetMailboxLocVal -eq 1) {
            $GetMailboxType = "On-Prem"
            $Mbxtypecolor = "Green"
        }
        Elseif ($GetMailboxLocVal -eq 2147483648) {
            $GetMailboxType = "Remote Mailbox"
            $Mbxtypecolor = "Yellow"
        }
        Else {
            $GetMailboxType = "Unknown"
            $Mbxtypecolor = "Red"
        }

        $DotForward = $null
        $DotForward = $objUser.properties.item("altRecipient")
        $ConactQuery = [ADSI]"LDAP://$DotForward"
        $EmailQ = $ConactQuery.get("mail")
        if ($DotForward -eq $null -or $DotForward -eq "< Null >") {
            $isDotForwardVal = " "
            $dotForwardColor = "Green"
        }
        Else {
            #Write-Host " $EmailQ "
            $isDotForwardVal = "$EmailQ"
            $dotForwardColor = "Yellow"
        }

        Write-Host " ================================================================"
        Write-Host " "
        Write-host "                   .__." -ForegroundColor Green
        Write-host "                   (oo)____" -ForegroundColor Green
        Write-host "                   (__)    )\" -ForegroundColor Green
        Write-host "                      ll--ll '" -ForegroundColor Green
        Write-Host " "
        Write-Host " ================================================================"
        Write-Host " Search Results for - " -NoNewline -BackgroundColor White -ForegroundColor Black
        Write-Host $GetDisplayName -ForegroundColor Black -BackgroundColor White
        Write-Host " ================================================================"
        Write-Host " Display Name         : "$GetDisplayName
        Write-Host " Login ID             : "$GetSAM
        Write-Host " UserPrincipalName    :  " -NoNewline
        Write-Host $GetUPN -ForegroundColor $UPNColor
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
        Write-Host " Mail Auto-Forward    :  " -NoNewline
        Write-Host $isDotForwardVal -ForegroundColor $dotForwardColor
        Write-Host " Mailbox Database     : "$GetHomeMDBName[1]
        Write-Host " Mailbox Creation     : "$GetMailboxCreation
        Write-Host " Mailbox Type         :  " -NoNewline
        Write-Host $GetMailboxType -ForegroundColor $Mbxtypecolor
        Write-Host " Profile Path         : "$GetProf
        Write-Host " Dial-In Access       :  " -NoNewline
        Write-Host $dialinStatus -ForegroundColor $Dialinstatuscolor
        Write-Host " Dial-In IP Address   : "$dialinIP
        Write-Host " LDAP Path            : "$GetLDAP

        $option = $null

        Write-Host " "
        Write-Host " ================================================================"
        Write-Host " "
        Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
        Write-Host " " -NoNewline
        Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
        Write-Host " " -NoNewline
        Write-Host " X " -NoNewline -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host " " -NoNewline
        Write-Host " Main Menu " -NoNewline -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host " " -NoNewline
        Write-Host " U " -NoNewline -ForegroundColor Black -BackgroundColor White
        Write-Host " " -NoNewline
        Write-Host " Unlock User " -NoNewline -ForegroundColor Black -BackgroundColor White
        Write-Host " " -NoNewline
        Write-Host " M " -NoNewline -ForegroundColor White -BackgroundColor DarkMagenta
        Write-Host " " -NoNewline
        Write-Host " More Info " -ForegroundColor White -BackgroundColor DarkMagenta
        Write-host " " -BackgroundColor Black
        $option = Read-Host " Enter Option "

        if ($option -eq "N" -or $option -eq $null -or $option -eq "") {
       
            NewSearch
        }
        Elseif ($option -eq "U" -or $option -eq "u") {
            Unlock $Query $UserQuery
        }
        Elseif ($option -eq "M" -or $option -eq "m") {
           
            $GetID = $null
            $objLdap = $null
            $Info = $null
            $split = $null
            $Info2 = $null
            $Query = $null

            MoreInfo $objUser

        }
        Elseif ($option -eq "E" -or $option -eq "e") {
            SayThanks
        }
        elseif ($option -eq "X" -or $option -eq "x") {
            Loading
        }
        Else {
            NewSearch
        }

    }



}

Function Unlock ($Query, $UserQuery) {
    # Write-host "Running Unlock - $Query" -ForegroundColor Yellow
    $GetSAM = $query.get("saMAccountName")
    # Write-host "SAMAccountName is - $GetSAM" -ForegroundColor Green
    Write-host " .Trying to Unlock... $GetSAM" -ForegroundColor Yellow -BackgroundColor Black
    Start-Sleep -Seconds 2
    $Query.InvokeSet("IsAccountLocked", $false)
    $Query.SetInfo()
    Write-host " .Refreshing the query for User... $GetSAM" -ForegroundColor Black -BackgroundColor Yellow
    Start-Sleep -Seconds 2
    cls
    SearchUser $UserQuery
}

Function MoreInfo ($objUser) {
    Write-host " "
    Write-Host " ____________________________________________________________ " -ForegroundColor Cyan
    Write-host " "
    $Notes = $objUser.properties.item("info")
    Write-Host " { Notes } " -ForegroundColor Yellow
    Write-host " $Notes "

    $Homemdb = $Query.get("HomeMDB")
    Write-Host " { HomeMDB } " -ForegroundColor Yellow
    Write-host " $Homemdb "

    $DotForward = $objUser.properties.item("altRecipient")
    if ($DotForward -eq $null -or $DotForward -eq "< Null >") {
        $DotForwardVal = " "
    }
    Else {
        $DotForwardVal = " $DotForward"
    }

    Write-Host " { Mobile }" -ForegroundColor Yellow
    Write-Host " "$objUser.Properties.item("Mobile")

    Write-Host " "

    Write-Host " { Autoforward }" -ForegroundColor Yellow
    Write-Host " $DotForwardVal "
    $ConactQuery = [ADSI]"LDAP://$DotForward"
    $EmailQ = $ConactQuery.get("mail")

    if ($DotForward -eq $null -or $DotForward -eq "< Null >") {
        Write-Host " "
    }
    Else {
        Write-Host " $EmailQ "
    }

    Write-Host " { Department }" -ForegroundColor Yellow
    $membershiplist = $objUser.properties.item("Department")
    Write-Host " "$membershiplist
    $TotalMem = $null
    $membershiplist = $objUser.properties.item("memberOf")
    $TotalMem = $membershiplist.count
    $i = 1
    $Mship = $null
    Write-Host " "
    Write-Host " { MemberOf } " -ForegroundColor Yellow
    Write-Host " Total Membership " -NoNewline
    Write-Host "{ " -ForegroundColor Green -NoNewline
    Write-Host "$TotalMem" -NoNewline
    Write-Host " }"-ForegroundColor Green
    Write-Host " "
    $GCount = 0
    forEach ($MshipCount in $membershiplist) {
        $GCount = $GCount + 1
    }
    ForEach ($Mship in $membershiplist) {
       
        $MemQuery = [ADSI]"LDAP://$Mship"
        $GroupTypeVal = $MemQuery.Properties.item("GroupType")
        # Write-Host "Group Value - $GroupTypeVal"
       
        Switch ($GroupTypeVal) {
            2 { $GroupType = '{ Global distribution group }' }
            4 { $GroupType = '{ Domain local distribution group }' }
            8 { $GroupType = '{ Universal distribution group }' }
            -2147483646 { $GroupType = '{ Global security group }' }
            -2147483644 { $GroupType = '{ Domain local security group }' }
            -2147483640 { $GroupType = '{ Universal security group }' }
        }

        #$MemSam = $MemSam + $MemQuery.Get("samaccountname") + " `n"
        Write-Host "    "$i. $MemQuery.Get("samaccountname") -NoNewline
        Write-host "  $GroupType" -ForegroundColor DarkGray
        $i++

        $Per = ($i / $GCount) * 100
        # Write-Progress -Activity "Fetching Group Membership" -PercentComplete $Per -Status "In-Progress"
       
    }

    Write-Host " "
    Write-Host " ____________________________________________________________ " -ForegroundColor Cyan
    Write-Host " "

    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "

    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        NewSearch
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        NewSearch
    }

}

Function NewSearch {
    Clear-Host
    loadlogo
    Write-host " "
    Write-host " [ PERFORMING USER QUERY ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "  
    $UserQuery = Read-Host " Enter Employee ID / Email ID / Login ID to Search {OR} ctrl+c to Exit "
    $Search = New-Object System.DirectoryServices.DirectorySearcher($ADsPath)
    if ($UserQuery -ne $null) {
        Write-Host " Searching User...."
        SearchUser $UserQuery
    }
    else {
        Write-Host " Enter Employee ID / Email ID to Search !!"
    }

}

Function SayThanks {
    Write-Host " Thank you for using this Script !!" -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    Exit
}

# =============================================================================================================
# =============================================================================================================
# GROUP QUERY
# =============================================================================================================
# =============================================================================================================


function ExportMembers ($Query) {
    $samaccountname = $Query.get("samaccountname")
    $mem = $Query.get("member")
    $memcount = $mem.count()
    Write-Host " Exporting Members for : $samaccountname"
    Write-Host " ======================================= " -ForegroundColor Yellow
    $i = 0
    foreach ($member in $mem) {
        $i = $i + 1
    }
    # $filename = (New-Guid).Guid
    Add-Content -Path ".\$samaccountname.csv" -Value "DisplayName , SAMAccountName , EmailID , Employeeid , ObjectClass"
    Write-Host " Total members found { " -NoNewline
    Write-Host "$i" -ForegroundColor Green -NoNewline
    Write-Host " }"
    Write-Host " =======================================" -ForegroundColor Yellow
    Write-host " "
    Write-Host " [ Exporting ] " -ForegroundColor DarkGreen -NoNewline
    Write-Host " Please wait !!"
    foreach ($member in $mem) {
        $mail = $null
        $employeeid = $null
        $LDAPInfo = "LDAP://" + $member
        $GQuery = [ADSI]"$LDAPInfo"
        $sam = $GQuery.get("samaccountname")
        $name = $GQuery.get("Name")
        $mail = $GQuery.get("mail")
        $employeeid = $GQuery.get("Employeeid")
        $objClassVal = $GQuery.get("ObjectClass")
        $ObjClassSplit = $objClassVal -split " "
        $objClass = $ObjClassSplit[-1]
       
        # Write-Host " $name  |  $sam    |    $mail    |  $employeeid | $ObjClass "
        Add-Content -Path ".\$samaccountname.csv" -Value "$name , $sam , $mail , $employeeid , $ObjClass"

    }
    $expto = (Get-Item .\$samaccountname.csv).FullName
    Write-Host " "
    Write-Host " Successfully Exported to : " -NoNewline
    Write-host "$expto" -ForegroundColor Yellow
   
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        NewGrpSearch
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        NewGrpSearch
    }
}

function ListMembers ($Query) {
    $samaccountname = $Query.get("samaccountname")
    $mem = $Query.get("member")
    $GroupMemCount = 0
    foreach ($countmeme in $mem) {
        $GroupMemCount = $GroupMemCount + 1
    }
    Write-Host " Listing Members for : $samaccountname"
    Write-Host " ======================================= " -ForegroundColor Yellow
    $i = 0
    foreach ($member in $mem) {
        $i = $i + 1
    }
   
   
    Write-Host " Total members found { " -NoNewline
    Write-Host "$i" -ForegroundColor Green -NoNewline
    Write-Host " }"
    Write-Host " =======================================" -ForegroundColor Yellow
    Write-host " "
    Write-Host " Name  ,  SAMAccountName , ObjClass " -ForegroundColor Green
    Write-Host " =======================================" -ForegroundColor Yellow
    Write-host " "
    $i = 0
    foreach ($member in $mem) {
        $mail = $null
        $employeeid = $null
        $LDAPInfo = "LDAP://" + $member
        $GQuery = [ADSI]"$LDAPInfo"
        $sam = $GQuery.get("samaccountname")
        $name = $GQuery.get("Name")
        $mail = $GQuery.get("mail")
        $employeeid = $GQuery.get("Employeeid")
        $objClassVal = $GQuery.get("ObjectClass")
        $ObjClassSplit = $objClassVal -split " "
        $objClass = $ObjClassSplit[-1]
       
       
        Write-host " $name , $sam , " -NoNewline
        if ($objClass -eq "group") {
            Write-Host $objClass -ForegroundColor Yellow
        }
        else {
            Write-Host $objClass -ForegroundColor White
        }
        $i++
        $Prog = ($i / $GroupMemCount) * 100
        # Write-Progress -Activity "Fetching Group Membership" -PercentComplete $Prog -Status "Work In Progress"
    }

    Write-Host " "
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        NewGrpSearch
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        NewGrpSearch
    }
   
}

function MoreGrpInfo ($Query) {
    $DistinguishedName = $Query.get("DistinguishedName")
    $getinfo = $Query.get("info")
    $info = ConvertTo-Json $getinfo
    $memof = $Query.get("MemberOf")
    if ($memof -eq $null) {
        $mems = " "
    }
    else {
       
        ForEach ($members in $memof) {
            $memsp1 = $members -split (",")
            $memsp2 = $memsp1[0] -split ("=")
            [array]$mems = $mems + $memsp2[1]
        }
    }
    $memsjson = ConvertTo-Json $mems
    Write-Host " { " -ForegroundColor Yellow
    Write-Host "      [ Distinguished Name ]" -ForegroundColor Green
    Write-Host "      $DistinguishedName" -ForegroundColor White
    Write-Host " } " -ForegroundColor Yellow
    Write-Host " { " -ForegroundColor Yellow
    Write-Host "      [ Info ]" -ForegroundColor Green
    Write-Host "      $info" -ForegroundColor White
    Write-Host " } " -ForegroundColor Yellow
    Write-Host " { " -ForegroundColor Yellow
    Write-Host "      [ Member Of ]" -ForegroundColor Green
    Write-Host "      $memsjson" -ForegroundColor White
    Write-Host " } " -ForegroundColor Yellow
   
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        NewGrpSearch
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        NewGrpSearch
    }
   
}

Function SearchGroup ($GroupQuery) {
    $search = New-Object DirectoryServices.DirectorySearcher([adsi]"")
    $Search.filter = "(&(objectCategory=Group)(objectClass=Group)(|(SamAccountName=$GroupQuery)(Name=$GroupQuery)(Mail=$GroupQuery)))"
    $objGroups = $search.FindAll()
    $i = 0
    ForEach ($objGroup in $objGroups) {
        $i = $i + 1
    }

    [int32]$ResultCount = $i

    if ($ResultCount -eq $null -or $ResultCount -eq 0) {
        Write-Host "      { " -ForegroundColor DarkYellow
        Write-Host "        Search resulted in NULL Output.... Possible cause !!" -ForegroundColor DarkYellow
        Write-Host "         { " -ForegroundColor DarkYellow
        Write-Host "            No connectivity to Active Directory " -ForegroundColor DarkYellow
        Write-Host "                 OR " -ForegroundColor Yellow
        Write-Host "            Unable to find AD Object " -NoNewline -ForegroundColor DarkYellow
        Write-Host "{ " -ForegroundColor Cyan -NoNewline
        Write-Host "$GroupQuery" -NoNewline -ForegroundColor Yellow
        Write-Host " }" -ForegroundColor Cyan -NoNewline
        Write-Host "  " -ForegroundColor DarkYellow
        Write-Host "         } " -ForegroundColor DarkYellow
        Write-Host "      } " -ForegroundColor DarkYellow
        Pause
        NewGrpSearch
    }
    Else {
        Write-Host " Got one Object { $i }" -ForegroundColor Green
    }


    ForEach ($objGroup in $objGroups) {
        $GetID = ""
        $GetUAC = ""
        $GetDisplayName = ""
        $GetSAM = ""
        $GetGrpType = ""
        $WCreated = ""
        $WChanged = ""
        $Description = ""
        $mail = ""
        $objLdap = $objGroup.GetDirectoryEntry()
        $Info = $objLdap.Path
        $split = $Info.Split(":")
        $Info2 = "LDAP:" + $split[1]
        $Query = [ADSI]"$Info2"
       
        $GetUAC = $query.get("UserAccountControl")
        $GetDisplayName = $query.get("DisplayName")
        $GetSAM = $query.get("saMAccountName")
        $GetGrpType = $query.get("GroupType")
        $WCreated = $Query.get("whenCreated")
        $WChanged = $Query.get("whenChanged")
        $Description = $Query.get("Description")
       
        $ManagedByVal = $Query.get("ManagedBy")
        $ManagedSplit = $ManagedByVal -split ","
        $ManagedSplit2 = $ManagedSplit[0] -split "="
        $ManagedBy = $ManagedSplit2[1]
        $mail = $Query.get("mail")
        $msExchRequireAuthToSendTo = $Query.get("msExchRequireAuthToSendTo")
       
    }

    Switch ($GetGrpType) {
        2 { $GroupType = 'Global distribution group' }
        4 { $GroupType = 'Domain local distribution group' }
        8 { $GroupType = 'Universal distribution group' }
        -2147483646 { $GroupType = 'Global security group' }
        -2147483644 { $GroupType = 'Domain local security group' }
        -2147483640 { $GroupType = 'Universal security group' }
    }
    Clear-Host
    Write-host " "
    Write-Host " ============================================================="
    Write-host "                   .__." -ForegroundColor Green
    Write-host "                   (oo)____" -ForegroundColor Green
    Write-host "                   (__)    )\" -ForegroundColor Green
    Write-host "                      ll--ll '" -ForegroundColor Green
    Write-Host " ============================================================="
    Write-host " Group Details for : " -nonewline
    Write-host $GroupQuery -ForegroundColor Green
    Write-Host " ============================================================="
    Write-host " "
    Write-Host " Display Name              : $GetDisplayName"
    Write-Host " SAM Account Name          : $GetSAM"
    Write-Host " Email ID                  : $mail"
    Write-Host " Group Type                : $GroupType"
    Write-Host " Description               : $Description"
    Write-Host " ManagedBy                 : $ManagedBy"
    Write-Host " RequireAuth To Send       : $msExchRequireAuthToSendTo"
    Write-Host " Created                   : $WCreated"
    Write-Host " Changed                   : $WChanged"
 


    $option = $null
    Write-Host " "
    Write-Host " ================================================================"
    Write-Host " "
    Write-Host " N " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " New Query " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " M " -ForegroundColor Black -BackgroundColor DarkMagenta -NoNewline
    Write-Host " " -NoNewline
    Write-Host " More Info " -ForegroundColor Black -BackgroundColor DarkMagenta -NoNewline
    Write-Host " " -NoNewline
    Write-Host " E " -ForegroundColor Black -BackgroundColor Cyan -NoNewline
    Write-Host " " -NoNewline
    Write-Host " Export Members " -ForegroundColor Black -BackgroundColor Cyan -NoNewline
    Write-Host " " -NoNewline
    Write-Host " X " -ForegroundColor Black -BackgroundColor Green -NoNewline
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green -NoNewline
    Write-Host " " -NoNewline
    Write-Host " L " -ForegroundColor White -BackgroundColor DarkBlue -NoNewline
    Write-Host " " -NoNewline
    Write-Host " List Members " -ForegroundColor White -BackgroundColor DarkBlue
    Write-host " " -BackgroundColor Black
    $option = Read-Host " > "

    if ($option -eq "n" -or $option -eq "N") {
        NewGrpSearch
    }
    elseif ($option -eq "m" -or $option -eq "M") {
        MoreGrpInfo $Query
    }
    elseif ($option -eq "e" -or $option -eq "E") {
        ExportMembers $Query
    }
    elseif ($option -eq "l" -or $option -eq "L") {
        ListMembers $Query
    }
    elseif ($option -eq "x" -or $option -eq "X") {
        Loading
    }
    else {
        NewGrpSearch
    }

}

function ShowLaps ($Query) {
    $GetLaps = $null
    $GetLaps = $Query.get("ms-Mcs-AdmPwd")
    Write-Host " Showing LAPS for the Computer"
    if ($null -eq $GetLaps) {
        Write-Host " "
        Write-Host " { " -ForegroundColor Blue
        Write-Host "    LAPS Password " -ForegroundColor Gray -NoNewline
        Write-Host ":" -ForegroundColor White -NoNewline
        Write-Host " Unable to fetch the LAPS " -ForegroundColor Yellow
        Write-Host " }" -ForegroundColor Blue
        Write-Host " "
    }
    else {
        Write-Host " "
        Write-Host " { " -ForegroundColor Blue
        Write-Host "    LAPS Password " -ForegroundColor Gray -NoNewline
        Write-Host ":" -ForegroundColor White -NoNewline
        Write-Host " $GetLaps " -ForegroundColor Green
        Write-Host " }" -ForegroundColor Blue
        Write-Host " "
    }
   

    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        NewCompSearch
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        NewCompSearch
    }
}

Function ListCompMembers ($Query) {
    $Memberof = $Query.get("Memberof")
    Write-Host "[ Member Of Details ]" -ForegroundColor Yellow
    ForEach ($members in $Memberof) {
        $member = $members -split (",")
        $mem = $member[0] -split "="
        $memval = $mem[1]
        Write-host "{ " -NoNewline -ForegroundColor Blue
        write-host $memval -ForegroundColor White -NoNewline
        Write-host " }" -ForegroundColor Blue
    }
    Write-Host " " -NoNewline
    Write-Host " N " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " New Query " -NoNewline -ForegroundColor Black -BackgroundColor Yellow
    Write-Host " " -NoNewline
    Write-Host " X " -NoNewline -ForegroundColor Black -BackgroundColor Green
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor Black -BackgroundColor Green  
    Write-Host " " -BackgroundColor Black
    $NextWhat = Read-Host " Enter Option "
   
    if ($NextWhat -eq "N" -or $NextWhat -eq "n") {
        NewCompSearch
    }
    elseif ($NextWhat -eq "X" -or $NextWhat -eq "x") {
        Loading
    }
    else {
        NewCompSearch
    }
}

Function SearchComp ($CompQuery) {
    $search = New-Object DirectoryServices.DirectorySearcher([adsi]"")
    $Search.filter = "(&(objectCategory=Computer)(objectClass=Computer)(|(SamAccountName=$CompQuery)(Name=$CompQuery)))"
    $objComps = $search.FindAll()
    $i = 0
    ForEach ($objComp in $objComps) {
        $i = $i + 1
    }

    [int32]$ResultCount = $i

    if ($ResultCount -eq $null -or $ResultCount -eq 0) {
        Write-Host "      { " -ForegroundColor DarkYellow
        Write-Host "        Search resulted in NULL Output.... Possible cause !!" -ForegroundColor DarkYellow
        Write-Host "         { " -ForegroundColor DarkYellow
        Write-Host "            No connectivity to Active Directory " -ForegroundColor DarkYellow
        Write-Host "                 OR " -ForegroundColor Yellow
        Write-Host "            Unable to find AD Object " -NoNewline -ForegroundColor DarkYellow
        Write-Host "{ " -ForegroundColor Cyan -NoNewline
        Write-Host "$CompQuery" -NoNewline -ForegroundColor Yellow
        Write-Host " }" -ForegroundColor Cyan -NoNewline
        Write-Host "  " -ForegroundColor DarkYellow
        Write-Host "         } " -ForegroundColor DarkYellow
        Write-Host "      } " -ForegroundColor DarkYellow
        Pause
        NewCompSearch
    }
    Else {
        Write-Host " Got one Object { $i }" -ForegroundColor Green
    }


    ForEach ($objComp in $objComps) {
        $GetID = ""
        $objLdap = $objComp.GetDirectoryEntry()
        $Info = $objLdap.Path
        $split = $Info.Split(":")
        $Info2 = "LDAP:" + $split[1]
        $Query = [ADSI]"$Info2"
       
        $GetDisplayName = $query.get("Name")
        $GetSAM = $query.get("saMAccountName")
        $DNSHostName = $Query.get("DNSHostName")
        $ObjectClass = $query.get("ObjectClass")
        $Operatingsystem = $query.get("operatingsystem")
        $useraccountcontrol = $query.get("useraccountcontrol")
        $description = $query.get("description")
        $WCreated = $Query.get("whenCreated")
        $WChanged = $Query.get("whenChanged")
        $distname = $Query.get("distinguishedname")

        $uac = switch ($useraccountcontrol) {
            1 { "SCRIPT" }
            2 { "ACCOUNTDISABLE" }
            8 { "HOMEDIR_REQUIRED" }
            16 { "LOCKOUT" }
            32 { "PASSWD_NOTREQD" }
            64 { "PASSWD_CANT_CHANGE" }
            128 { "ENCRYPTED_TEXT_PWD_ALLOWED" }
            256 { "TEMP_DUPLICATE_ACCOUNT" }
            512 { "NORMAL_ACCOUNT" }
            2048 { "INTERDOMAIN_TRUST_ACCOUNT" }
            4096 { "Workstation/server" }
            8192 { "SERVER_TRUST_ACCOUNT" }
            65536 { "DONT_EXPIRE_PASSWORD" }
            131072 { "MNS_LOGON_ACCOUNT" }
            262144 { "SMARTCARD_REQUIRED" }
            524288 { "TRUSTED_FOR_DELEGATION" }
            1048576 { "NOT_DELEGATED" }
            2097152 { "USE_DES_KEY_ONLY" }
            4194304 { "DONT_REQ_PREAUTH" }
            8388608 { "PASSWORD_EXPIRED" }
            16777216 { "TRUSTED_TO_AUTH_FOR_DELEGATION" }
            67108864 { "PARTIAL_SECRETS_ACCOUNT" }
            532480 { "Domain Controller" }
            Default { "$useraccountcontrol" }
        }
       
    }

   
    Clear-Host
    Write-host " "
    Write-Host " ============================================================="
    Write-host "                   .__." -ForegroundColor Green
    Write-host "                   (oo)____" -ForegroundColor Green
    Write-host "                   (__)    )\" -ForegroundColor Green
    Write-host "                      ll--ll '" -ForegroundColor Green
    Write-Host " ============================================================="
    Write-host " Computer Details for : " -nonewline
    Write-host $CompQuery -ForegroundColor Green
    Write-Host " ============================================================="
    Write-host " "
    Write-Host " Display Name              : $GetDisplayName"
    Write-Host " SAM Account Name          : $GetSAM"
    Write-Host " DNSHostName               : $DNSHostName"
    Write-Host " ObjectClass               : $ObjectClass"
    Write-Host " Operatingsystem           : $Operatingsystem"
    if ($uac -eq "Domain Controller") {
        Write-Host " Useraccountcontrol        : " -nonewline
        Write-host $uac -ForegroundColor Yellow
    }
    else {
        Write-Host " Useraccountcontrol        : $uac"
    }
    Write-Host " Description               : $description"
    Write-Host " Created                   : $WCreated"
    Write-Host " Changed                   : $WChanged"
    Write-Host " distinguishedname         : $distname"    
 


    $option = $null
    Write-Host " "
    Write-Host " ================================================================"
    Write-Host " "
    Write-Host " N " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " New Query " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " L " -ForegroundColor White -BackgroundColor DarkBlue -NoNewline
    Write-Host " " -NoNewline
    Write-Host " List Members " -ForegroundColor White -BackgroundColor DarkBlue -NoNewline
    Write-Host " " -NoNewline
    Write-Host " S " -ForegroundColor White -BackgroundColor DarkYellow -NoNewline
    Write-Host " " -NoNewline
    Write-Host " Show LAPS " -ForegroundColor White -BackgroundColor DarkYellow -NoNewline
    Write-Host " " -NoNewline
    Write-Host " X " -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor White -BackgroundColor DarkMagenta
    $option = Read-Host " > "

    if ($option -eq "n" -or $option -eq "N") {
        NewCompSearch
    }
    elseif ($option -eq "l" -or $option -eq "L") {
        ListCompMembers $Query
    }
    elseif ($option -eq "s" -or $option -eq "S") {
        ShowLaps $Query
    }
    elseif ($option -eq "x" -or $option -eq "X") {
        Loading
    }
    else {
        NewCompSearch
    }

}

Function NewCompSearch {
    Clear-Host
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING COMPUTER QUERY ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "
 
    Write-Host " Enter Computer " -ForegroundColor White -NoNewline
    Write-Host " SAMAccountName " -ForegroundColor Yellow -NoNewline
    Write-host "/ " -ForegroundColor Blue -NoNewline
    Write-host "Display Name " -ForegroundColor Yellow -NoNewline
    Write-host "{OR}" -ForegroundColor Gray -NoNewline
    Write-host " ctrl+c to Exit " -ForegroundColor White
    $CompQuery = Read-Host " [~] "
    $Search = New-Object System.DirectoryServices.DirectorySearcher($ADsPath)
    if ($CompQuery -ne $null) {
        Write-Host " Searching Computer...."
        SearchComp $CompQuery
    }
    else {
        Write-Host " Enter Computer SAMAccountName / Display Name to Search !!"
    }

}
Function NewGrpSearch {
    Clear-Host
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING GROUP QUERY ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "
     
    Write-Host " Enter Group " -ForegroundColor White -NoNewline
    Write-Host " SAMAccountName " -ForegroundColor Yellow -NoNewline
    Write-host "/ " -ForegroundColor Blue -NoNewline
    Write-host "Email ID " -ForegroundColor Yellow -NoNewline
    Write-host "{OR}" -ForegroundColor Gray -NoNewline
    Write-host " ctrl+c to Exit " -ForegroundColor White
    $GroupQuery = Read-Host " [~] "
    $Search = New-Object System.DirectoryServices.DirectorySearcher($ADsPath)
    if ($GroupQuery -ne $null) {
        Write-Host " Searching Group...."
        SearchGroup $GroupQuery
    }
    else {
        Write-Host " Enter Group SAMAccountName / Email ID to Search !!"
    }

}

Function ObjectExport {
    Clear-Host
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING Object Export ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "
    $OUPath = Read-Host " Enter the OU path for Search [Ex - Ou=TestOU,DC=appu,DC=local] : "
    Write-Host " ======================"
    Write-Host " Select the Option"
    Write-Host " ======================"
    Write-Host " 1. Export All Users from specific OU & Sub OU"
    Write-Host " 2. Export All Computers from specific OU & Sub OU"
    Write-Host " 3. Export All Objects from specific OU & Sub OU"
    $Ask = Read-Host " Prompt > "

    if ($Ask -eq 1) {
        # All Users
        # ======================
        Write-Host " Exporing All Users from : $OUPath" -ForegroundColor Green
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$OUPath"
        $searcher.SearchScope = "Subtree"
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        $searcher.PropertiesToLoad.Add("name")
        $searcher.PropertiesToLoad.Add("userprincipalname")
        $searcher.PropertiesToLoad.Add("samaccountname")
        $searcher.PropertiesToLoad.Add("distinguishedname")
        $searcher.PropertiesToLoad.Add("whencreated")

        $results = $searcher.FindAll()
        forEach ($result in $results) {
            $properties = $result.Properties

            $login = $login + @([pscustomobject]@{name = $($properties.name); samaccountname = $($properties.samaccountname); userprincipalname = $($properties.userprincipalname); whencreated = $($properties.whencreated) })
        }
        $guid = (New-Guid).Guid
        $login | Export-Csv -Path .\AllUsers_$guid.csv -NoTypeInformation
        Write-Host " Exported to : " -NoNewline
        Write-Host ".\AllUsers_$guid.csv" -ForegroundColor Yellow
    }
    elseif ($Ask -eq 2) {

        # All Computers
        # ======================
        Write-Host " Exporing All Computers from : $OUPath" -ForegroundColor Green
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$OUPath"
        $searcher.SearchScope = "Subtree"
        $searcher.Filter = "(&(objectClass=computer))"
        $searcher.PropertiesToLoad.Add("name")
        $searcher.PropertiesToLoad.Add("whencreated")
        $searcher.PropertiesToLoad.Add("samaccountname")
        $searcher.PropertiesToLoad.Add("distinguishedname")
        $searcher.PropertiesToLoad.Add("operatingsystemversion")

        $results = $searcher.FindAll()
        forEach ($result in $results) {
            $properties = $result.Properties
            $login = $login + @([pscustomobject]@{name = $($properties.name); samaccountname = $($properties.samaccountname); distinguishedname = $($properties.distinguishedname); operatingsystemversion = $($properties.operatingsystemversion); whencreated = $($properties.whencreated) })
        }
        $guid = (New-Guid).Guid
        $login | Export-Csv -Path .\AllComputers_$guid.csv -NoTypeInformation
        Write-Host " Exported to : " -NoNewline
        Write-Host ".\AllComputers_$guid.csv" -ForegroundColor Yellow
    }
    elseif ($Ask -eq 3) {

        # All Objects
        # ======================
        Write-Host " Exporing All Objects from : $OUPath" -ForegroundColor Green
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$OUPath"
        $searcher.Filter = "(objectClass=*)"
        $searcher.SearchScope = "Subtree"
        $searcher.PropertiesToLoad.Add("name")
        $searcher.PropertiesToLoad.Add("WhenCreated")
        $searcher.PropertiesToLoad.Add("samaccountname")
        $searcher.PropertiesToLoad.Add("distinguishedname")
        $searcher.PropertiesToLoad.Add("objectclass")

        $results = $searcher.FindAll()
        forEach ($result in $results) {
            $properties = $result.Properties
          
            $login = $login + @([pscustomobject]@{name = $($properties.name); samaccountname = $($properties.samaccountname); distinguishedname = $($properties.distinguishedname); objectclass = $($properties.objectclass); whencreated = $($properties.whencreated) })
        }
        $guid = (New-Guid).Guid
        $login | Export-Csv -Path .\AllObjects_$guid.csv -NoTypeInformation
        Write-Host " Exported to : " -NoNewline
        Write-Host ".\AllObjects_$guid.csv" -ForegroundColor Yellow
    }
    else {
        Write-Host " Invalid Option Selected !!" -ForegroundColor Red
    }

    $option = $null
    Write-Host " "
    Write-Host " ================================================================"
    Write-Host " "
    Write-Host " N " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " New Query " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " X " -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor White -BackgroundColor DarkMagenta
    $option = Read-Host " > "

    if ($option -eq "n" -or $option -eq "N") {
        ObjectExport
    }
    elseif ($option -eq "x" -or $option -eq "X") {
        Loading
    }
    else {
        ObjectExport
    }

}

function xxd {
    Clear-Host
    loadlogo
    Write-host " "
    Write-Host " [ PERFORMING XXD QUERY ] " -ForegroundColor Black -BackgroundColor Cyan
    Write-host " "
    $FilePath = Read-Host " Enter the file path [FQDN] to view the HEX values : "


    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $lineSize = 16
    
    # Display the header
    Write-Host ("Offset(Hex)  " + ("Byte Values".PadRight(47)) + " |ASCII|")

    # Iterate through bytes
    for ($i = 0; $i -lt $bytes.Length; $i += $lineSize) {
        $chunk = $bytes[$i..([Math]::Min($i + $lineSize - 1, $bytes.Length - 1))]
        $offset = $i.ToString("X8")
        $hex = ($chunk | ForEach-Object { $_.ToString("X2") }) -join " "
        $ascii = ($chunk | ForEach-Object {
                if ($_ -ge 32 -and $_ -le 126) {
                    [char]$_
                }
                else {
                    "."
                }
            }) -join ""

        Write-Host ("$offset  $hex".PadRight(57) + " |$ascii|")
    }


    $option = $null
    Write-Host " "
    Write-Host " ================================================================"
    Write-Host " "
    Write-Host " N " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " New Query " -ForegroundColor Black -BackgroundColor White -NoNewline
    Write-Host " " -NoNewline
    Write-Host " X " -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
    Write-Host " " -NoNewline
    Write-Host " Main Menu " -ForegroundColor White -BackgroundColor DarkMagenta
    $option = Read-Host " > "

    if ($option -eq "n" -or $option -eq "N") {
        xxd
    }
    elseif ($option -eq "x" -or $option -eq "X") {
        Loading
    }
    else {
        xxd
    }

}

function MainMenu {
    Clear-Host
    $currentDomain = $null
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $CurrDomName = $currentDomain.Name
    if ($currentDomain -ne $null) {
        $domMsg = " You have connected to Domain - $CurrDomName"
    }
    else {
        $domMsg = " Unable to connect to any Domain. Active Directory related query cannot be performed !"
    }
    Write-Host " "
    loadlogo
    Write-Host " " -NoNewline
    Write-Host "   Script By : Binu Balan | Version : $Version    " -ForegroundColor Black -BackgroundColor DarkGray    
    Write-Host "   $domMsg" -ForegroundColor Gray
    Write-Host " "
    Write-Host " Enter the option to for the Query type "
    Write-Host "      1. " -ForegroundColor Green -NoNewline
    Write-host "User Query" -ForegroundColor White
    Write-Host "      2. " -ForegroundColor Green -NoNewline
    Write-Host "Group Query" -ForegroundColor White
    Write-Host "      3. " -ForegroundColor Green -NoNewline
    Write-Host "Computer Query" -ForegroundColor White
    Write-Host "      4. " -ForegroundColor Green -NoNewline
    Write-Host "TCP Port Query" -ForegroundColor White
    Write-Host "      5. " -ForegroundColor Green -NoNewline
    Write-Host "Temp File Deletion" -ForegroundColor White
    Write-Host "      6. " -ForegroundColor Green -NoNewline
    Write-Host "Random Password Generator" -ForegroundColor White
    Write-Host "      7. " -ForegroundColor Green -NoNewline
    Write-Host "Check SSL Certificate on Remote Port" -ForegroundColor White
    Write-Host "      8. " -ForegroundColor Green -NoNewline
    Write-Host "SSL Version Scan on a Port" -ForegroundColor White
    Write-Host "      9. " -ForegroundColor Green -NoNewline
    Write-Host "Convert To or From Base64" -ForegroundColor White
    Write-Host "      10. " -ForegroundColor Green -NoNewline
    Write-Host "Encrypt String to Base64 OR Decrypt encrypted Base64 to String" -ForegroundColor White
    Write-Host "      11. " -ForegroundColor Green -NoNewline
    Write-Host "Get file HASH/s" -ForegroundColor White
    Write-Host "      12. " -ForegroundColor Green -NoNewline
    Write-Host "Get file XXD" -ForegroundColor White
    Write-Host "      13. " -ForegroundColor Green -NoNewline
    Write-Host "Object Export" -ForegroundColor White
    Write-Host " "
    $Option = Read-Host(" Prompt > ")
    If ($Option -eq 1) {
        NewSearch
    }
    elseif ($option -eq 2) {
        NewGrpSearch
    }
    elseif ($option -eq 3) {
        NewCompSearch
    }
    elseif ($option -eq 4) {
        PortQuery
    }
    elseif ($option -eq 5) {
        TempFileDeletion
    }
    elseif ($option -eq 6) {
        RandomPass
    }
    elseif ($option -eq 7) {
        ssl-clean
    }
    elseif ($option -eq 8) {
        sslscan-clean
    }
    elseif ($option -eq 9) {
        converttoandfrombase64
    }
    elseif ($option -eq 10) {
        EncryptDecryptString
    }
    elseif ($option -eq 11) {
        GetHASHofFile
    }
    elseif ($option -eq 12) {
        xxd
    }
    elseif ($option -eq 13) {
        ObjectExport
    }
    else {
        Write-host "[Error] " -ForegroundColor Red -NoNewline
        Write-Host " You have entered invalid option !! Exiting..."
        Start-Sleep -Seconds 2
    }
}
Loading
