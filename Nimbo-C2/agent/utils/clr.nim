import std/[strformat, strutils]
import winim/[clr]

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

