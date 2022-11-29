from typing import Callable, Optional

from qiling import Qiling

from .auto import dump as auto_dump


class DumpHook:
    dump_func: Callable[[Qiling, int], bytes]
    emu_stop: bool
    result: Optional[bytes] = None

    def __init__(self, dump_func: Callable[[Qiling, int], bytes] = auto_dump, **kwargs):
        self.dump_func = dump_func
        self.emu_stop = kwargs.pop("emu_stop", True)

    def __call__(self, ql: Qiling):
        self.result = bytes(self.dump_func(ql, ql.arch.regs.arch_pc))
        if self.emu_stop:
            ql.emu_stop()


dump_hook = DumpHook()

__all__ = ["dump_hook", "DumpHook"]
