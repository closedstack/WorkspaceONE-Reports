# Workspace ONE / Airwatch Reports with Cert Auth
Sample code for Doing Cert Based Auth to Connect to Workspace ONE UEM (aka Airwatch)
The CMS signer can sign arbitrary data and produces a Cryptographic Message Syntax per (RFC 3852/5652)
prepended by CMSURL`1 

##### Based on code from : https://dexterposh.blogspot.com/2015/01/powershell-rest-api-basic-cms-cmsurl.html
I have taken the liberty to rename it and make this a bit more usable for enterprise environments

### Steps to get this to work:
Create a admin user in Workspace ONE and give it the appropriate role with API Permissions.
Set Authentication Type to be certificate based. Generate a Client Cert, provide a password and export the cert (save the password)
#Scheduling the report job
Create a conf file similar to as.conf.sample with your instance, tenant key, path to p12/pfx file downloaded and the password to the p12 file
This is how you convert a string to a SecureString. Keep in mind that it can only be decrypted by the same account on the same machine where the securestring was created.

ConvertTo-SecureString 'Hello' -AsPlainText | ConvertFrom-SecureString 

### Output
This sample saves the result to a CSV file, you could very easily write it to a database or email it as you please.
