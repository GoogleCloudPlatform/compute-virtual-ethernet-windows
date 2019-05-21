# To register or unregister gvnic helper in netsh registry
# Usage:
# To register : .\Register-GvnicHelper.ps1 register [PATH TO DLL]
# To unregister : .\Register-GvnicHelper.ps1 unregister

param (
  [parameter(Mandatory=$true)]
  [ValidateSet('register', 'unregister')]
  [string]$Command,
  [string]$DllPath
)

$REGISTRY_PATH = 'HKLM:SOFTWARE\Microsoft\NetSh'
$NAME = 'gvnichelper'

function Register-GvnicHelper {
    <#
    .SYNOPSYS
    Registers gvnic helper dll in netsh registry
    .PARAMETER
    gvnichelper dll path
    #>
    param (
    [parameter(Mandatory=$true)]
    [string]$DllPath
    )
    New-ItemProperty -Path $REGISTRY_PATH -Name $NAME -Value $DllPath -PropertyType 'String'
}

function Unregister-GvnicHelper {
    <#
    .SYNONPSYS
    Unregisters gvnic helper dll from netsh registry
    #>
    Remove-ItemProperty -Path $REGISTRY_PATH -Name $NAME -ErrorAction SilentlyContinue
}

if ($command -eq 'register') {
    Register-GvnicHelper $DllPath
}
if ($command -eq 'unregister') {
    Unregister-GvnicHelper
}


