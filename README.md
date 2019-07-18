# LSA-Rights-Library
[![Build Status](https://dev.azure.com/wightsci/GitHubRepos/_apis/build/status/wightsci.LSA-Rights-Library?branchName=master)](https://dev.azure.com/wightsci/GitHubRepos/_build/latest?definitionId=2&branchName=master)

Windows library to manage LSA rights and privileges. Designed to be used with PowerShell as a binary file or a textual Type within a script.
Functionality:
* Add right(s)
* Remove right(s)
* List rights

## Using the binary DLL.
Download the dll and store it somewhere on your path.

In your PowerShell script, add the dll as a type:
```PowerShell
Add-Type -Path 'LSA Rights Library.dll'
```
You can now use ```New-Object``` to create an instance of the ```LocalSecurityAuthorityController``` class:
```PowerShell
$lsa = New-Object LSAController.LocalSecurityAuthorityController
```

## Using the textual type
Download the ControllerClass.cs C# file.
load the contents of the file in your PowerShell script at runtime (using ```Get-Content```) or 
alternatively paste it in to a here-string.

```PowerShell
Add-Type -Path 'ControllerClass.cs'
```
or

```PowerShell
$controllerClass = @'
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
...
```
followed by
```PowerShell
Add-Type -TypeDefinition $controllerClass
```
You can now use ```New-Object``` to create an instance of the ```LocalSecurityAuthorityController``` class:
```PowerShell
$lsa = New-Object LSAController.LocalSecurityAuthorityController
```



## Methods
For the ```privelegeName``` parameter you can use the name found in most Microsoft documentation (```SeServiceLogonRight, SeBackupPrivilege``` etc.) 
or you can use one of the ```LocalSecurityAuthorityRights``` declared in the dll:

```
LogonAsService
LogonAsBatchJob
InteractiveLogon
NetworkLogon
GenerateSecurityAudits
Backup
SetTime
RemoteShutdown
DenyLogonAsService
DenyLogonAsBatchJob
DenyInteractiveLogon
DenyNetworkLogon
```

#### GetAccountsWithRight(string privilegeName)
Returns a System.Collections.Generic.IList[string] of Accounts (Users or Groups) with the specified right.

#### GetRightsForAccount(string accountName)
Returns a System.Collections.Generic.IList[string] of Rights held by the specified  Account.

#### RemoveRight(string accountName, string privilegeName)
Removes the specified Right from the specified Account.

#### RemoveRights(string accountName, System.Collections.Generic.IList[string] rights)
Removes the specified Rights from the specified Account.

#### SetRight(string accountName, string privilegeName)
Sets the specified Right for the specified Account.

#### SetRights(string accountName, System.Collections.Generic.IList[string] rights)
Sets the specified Rights for the specified Account.