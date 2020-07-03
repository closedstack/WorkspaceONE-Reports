#Sample code for Doing Cert Based Auth to Connect to Workspace ONE UEM (aka Airwatch)
#The CMS signer can sign arbitrary data and produces a Cryptographic Message Syntax per (RFC 3852)
#prepended by CMSURL`1 
#Credit for the Function : https://dexterposh.blogspot.com/2015/01/powershell-rest-api-basic-cms-cmsurl.html
#I have taken the liberty to rename it and make this a bit more usable for enterprise environments
function Get-CMSSignedURL
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input the URL to be
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [uri]$URL,

        # Specify the Certificate to be used
        [Parameter(Mandatory=$true,
                    ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Begin
    {
        Write-Verbose -Message '[Get-CMSSignedURL] - Starting Function'

    }
    Process
    {
       TRY
       {
            #Get the Absolute Path of the URL encoded in UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Url.AbsolutePath))

            #Open Memory Stream passing the encoded bytes
            $MemStream = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes) -ErrorAction Stop

            #Create the Signed CMS Object providing the ContentInfo (from Above) and True specifying that this is for a detached signature
            $SignedCMS = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $MemStream,$true -ErrorAction Stop

            #Create an instance of the CMSigner class - this class object provide signing functionality
            $CMSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $Certificate -Property @{IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly} -ErrorAction Stop

            #Add the current time as one of the signing attribute
            $null = $CMSigner.SignedAttributes.Add((New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime))

            #Compute the Signatur
            $SignedCMS.ComputeSignature($CMSigner)

            #As per the documentation the authorization header needs to be in the format 'CMSURL `1 <Signed Content>'
            #One can change this value as per the format the Vendor's REST API documentation wants.
            $CMSHeader = '{0}{1}{2}' -f 'CMSURL','`1 ',$([System.Convert]::ToBase64String(($SignedCMS.Encode())))
            Write-Output -InputObject $CMSHeader
        }
        Catch
        {
            Write-Error -Exception $_.exception -ErrorAction stop
        }
    }
    End
    {
        Write-Verbose -Message '[Get-CMSSignedURL] - Ending Function'
    }
} 

#We need to build this header each time the URL Changes, like when paging through data
#So Making this a function
Function Get-AuthHeader{
    PARAM(
        [Parameter(Mandatory=$true)]
        [uri] $Uri,

        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert,
        
        [Parameter(Mandatory=$true)]
        [string] $API_KEY
    )
    $Headers = @{
        'Authorization' = "$(Get-CMSSignedURL -URL $Uri -Certificate $Cert)";
        'AW-Tenant-Code' = $API_KEY;
        'Content-type' = 'application/json'
    }
    return $Headers
}

#This is the Client Certificate issued from the UEM console
#Makes sense to have things like your instance URL, API Key, 
#Certificate issued from the UEM console and Password set for it
#Password should be stored as a securestring (do otherwise at your own risk) Here is how to
#ConvertTo-SecureString 'Hello' -AsPlainText | ConvertFrom-SecureString 
#This can only be decrypted by the same account on the same machine where the securestring was created
$configFile = "./as.conf"
$config = Get-Content -Path $configFile | ConvertFrom-Json
$API_KEY = $($config.API_KEY)
$cert = Get-PfxCertificate -FilePath $($config.certFile) -Password (ConvertTo-SecureString  $($config.certPass))

$resultFile = "C:\Scripts\MDMDevices.csv"
$devices = @()
$i = 0
$pageCount = 0
$pageSize = 1000
#For more than pagesize devices (1000 here) - we would need to loop multiple times
do{
    $deviceUri = "https://$($config.baseURL)/api/mdm/devices/search?pagesize=$pageSize&page=$i"
    $Headers = Get-AuthHeader -Uri $deviceUri -Cert $cert -API_KEY $API_KEY
    $result = Invoke-RestMethod -Method Get -Uri $deviceUri -Headers $Headers -ErrorAction Stop 
    $devices += $($result.Devices)
    $pageCount = [Math]::Ceiling($result.Total /  $result.PageSize)
    $result.Page
    $i++
}while($i -lt $pageCount)

$devices | Where-Object {$_.EnrollmentStatus -eq 'Enrolled'} | Select-Object -Property UserName, EnrollmentStatus, UserEmailAddress, Platform, Model, `
OperatingSystem, LastSeen, SerialNumber, MacAddress, Imei, DeviceFriendlyName, LocationGroupName, ComplianceStatus, `
CompromisedStatus, LastComplianceCheckOn, LastCompromisedCheckOn, IsSupervised  | 
    sort -property UserName | Export-Csv -NoTypeInformation -Path $resultFile