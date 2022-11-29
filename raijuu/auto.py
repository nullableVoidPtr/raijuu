from qiling import Qiling
from qiling.const import QL_OS

from .pe import dump as pe_dump


def dump(ql: Qiling, original_entrypoint: int) -> bytes:
    if ql.os.type == QL_OS.WINDOWS:
        pe_image = ql.loader.images[0]
        image_base = pe_image.base
        image_size = pe_image.end - pe_image.base
        if not (pe_image.base < original_entrypoint < pe_image.end):
            try:
                image_base, image_size = next(
                    (
                        (base, end - base)
                        for base, end, _, _, _ in ql.mem.get_mapinfo()
                        if base < original_entrypoint < end
                    )
                )
            except StopIteration as exc:
                raise ValueError("Cannot find suitable memory section") from exc
        return pe_dump(ql, image_base, image_size, original_entrypoint)
    elif ql.os.type in [QL_OS.LINUX, QL_OS.FREEBSD]:
        pass
        # TODO
    raise NotImplementedError(f"Cannot dump with OS type {ql.os.type}")


__all__ = ["dump"]
