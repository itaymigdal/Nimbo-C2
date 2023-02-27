from os import path


def read_ps_module(ps_module_filename):
    ps_module_filename = path.join(path.dirname(__file__), "ps_modules", ps_module_filename)
    with open(ps_module_filename, "rt") as f:
        return f.read()

# modules
pstree = read_ps_module("pstree.ps1")
software = read_ps_module("software.ps1")