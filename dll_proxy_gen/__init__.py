"""
dll-proxy-gen: DLL proxy generator for Windows DLL hijacking via export forwarding.

Parse a target DLL's export table and emit ready-to-compile C source, .def, and
CMakeLists.txt files that forward every call to an original renamed copy of the DLL
while running an optional payload on DLL_PROCESS_ATTACH.
"""

__version__ = "0.1.0"
__all__ = ["parser", "generator", "payload", "cli"]
