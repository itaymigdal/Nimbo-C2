function Get-Bitness {
    param ([System.Diagnostics.Process]$Process)
    $modules = $process.modules
    foreach ($module in $modules) {
        $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
        if ($file -eq "wow64.dll") {
            return "x32"
        } 
    }
    return "x64"
}

function Get-ProcessTree {
    [CmdletBinding()]
    param([int]$IndentSize = 2)
    
    $indentSize = [Math]::Max(1, [Math]::Min(12, $indentSize))
    $processes = Get-WmiObject Win32_Process
    $pids = $processes | select -ExpandProperty ProcessId
    $parents = $processes | select -ExpandProperty ParentProcessId -Unique
    $liveParents = $parents | ? { $pids -contains $_ }
    $deadParents = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents `
    | select -ExpandProperty InputObject
    $processByParent = $processes | Group-Object -AsHashTable ParentProcessId

    function Write-ProcessTree($process, [int]$level = 0) {
        $id = $process.ProcessId
        $parentProcessId = $process.ParentProcessId
        if ($IsElevated)
        { $process = Get-Process -Id $id -IncludeUserName }
        else
        { $process = Get-Process -Id $id }
        $indent = New-Object String(' ', ($level * $indentSize))
        $process `
        | Add-Member NoteProperty Process_Id $process.id -PassThru `
        | Add-Member NoteProperty Process_Name "`t$indent$($process.Name).exe" -PassThru `
        | Add-Member NoteProperty Bitness "$((Get-Bitness $process))" -PassThru 

        $processByParent.Item($id) `
        | ? { $_ } `
        | % { Write-ProcessTree $_ ($level + 1) }
    }

    $processes `
    | ? { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } `
    | % { Write-ProcessTree $_ }
}

$IsElevated = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Administrators")

if ($IsElevated) 
{ Get-ProcessTree -Verbose | select Process_Id, Process_Name, UserName, Bitness }
else 
{ Get-ProcessTree -Verbose | select Process_Id, Process_Name, Bitness }