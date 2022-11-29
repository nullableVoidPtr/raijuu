from dataclasses import dataclass
from typing import Optional

from lief import PE
from qiling import Qiling
from qiling.loader.pe import QlLoaderPE


@dataclass
class _ImportEntry:
    module: str
    name: str
    iat_rva: int
    ordinal: int


@dataclass
class _Import:
    name: str
    entries: list[_ImportEntry]


@dataclass
class _UnresolvedImports:
    entries: list[int]


@dataclass
class _ImageImportDescriptor:
    original_first_thunk: int
    time_date_stamp: int
    forwarder_chain: int
    name: int
    first_thunk: int

    def __bytes__(self):
        return (
            self.original_first_thunk.to_bytes(4, "little")
            + self.time_date_stamp.to_bytes(4, "little")
            + self.forwarder_chain.to_bytes(4, "little")
            + self.name.to_bytes(4, "little")
            + self.first_thunk.to_bytes(4, "little")
        )


def import_tree_from_table(
    ql: Qiling, base: int, iat_start: int, iat_size: int
) -> list[_Import | _UnresolvedImports]:
    reverse_resolved: list[int | _ImportEntry] = []

    loader: QlLoaderPE = ql.loader  # type: ignore
    for iat_address in range(iat_start, iat_start + iat_size, ql.arch.pointersize):
        iat_value = ql.mem.read_ptr(iat_address)
        imp_data = loader.import_symbols.get(iat_value, None)
        reverse_resolved.append(
            _ImportEntry(
                imp_data["dll"] + ".dll",
                imp_data["name"].decode(),
                iat_address - base,
                imp_data["ordinal"],
            )
            if imp_data is not None
            else iat_address
        )

    import_tree: list[_Import | _UnresolvedImports] = []
    for entry in reverse_resolved:
        if len(import_tree) == 0:
            import_tree.append(
                _Import(entry.module, [entry])
                if isinstance(entry, _ImportEntry)
                else _UnresolvedImports([entry])
            )
            continue

        last = import_tree[-1]
        if isinstance(entry, _ImportEntry):
            if isinstance(last, _Import) and last.name == entry.module:
                last.entries.append(entry)
            else:
                import_tree.append(_Import(entry.module, [entry]))
        else:
            if isinstance(last, _UnresolvedImports):
                last.entries.append(entry)
            else:
                import_tree.append(_UnresolvedImports([entry]))

    return import_tree


def search_iat(ql: Qiling, start: int, size: int) -> tuple[int, int]:
    known_api_addresses = set()

    loader: QlLoaderPE = ql.loader  # type: ignore
    for mod in loader.import_address_table.values():
        known_api_addresses.update(mod.values())

    high_api_bits = set(
        (a >> 16).to_bytes(ql.arch.pointersize - 2, "little")
        for a in known_api_addresses
    )

    partial_matches = set()
    for bits in high_api_bits:
        partial_matches.update(
            tail - 2 for tail in ql.mem.search(bits, start, start + size)
        )

    sorted_sequences = []
    for match in sorted(partial_matches):
        if ql.mem.read_ptr(match) not in known_api_addresses:
            continue

        for seq in sorted_sequences:
            if seq[-1] + ql.arch.pointersize == match:
                seq.append(match)
                break
        else:
            sorted_sequences.append([match])

    sorted_sequences = [seq for seq in sorted_sequences if len(seq) > 1]

    found_iat = max(sorted_sequences, key=len)
    iat_start = found_iat[0]
    iat_size = len(found_iat) * ql.arch.pointersize

    return (iat_start, iat_size)


def build_idata(
    ql: Qiling,
    tree: list[_Import | _UnresolvedImports],
    section_base_rva: int,
    **kwargs,
) -> tuple[PE.Section, int, int]:
    # TODO: preprocess tree by identifying gaps in IAT and splitting modules
    def lookup_table_len(l: list[int]):
        return ql.arch.pointersize * len(l)

    rebuild_iat = kwargs.pop("rebuild_iat", False)  # TODO

    lookup_tables: list[list[int]] = [[0] * (len(imp.entries) + 1) for imp in tree]

    descriptors_start = sum(map(lookup_table_len, lookup_tables))
    descriptors = [
        _ImageImportDescriptor(
            section_base_rva + sum(lookup_table_len(t) for t in lookup_tables[:i]),
            0,
            0,
            0,
            imp.entries[0].iat_rva if isinstance(imp, _Import) else imp.entries[0],
        )
        for i, imp in enumerate(tree)
    ] + [_ImageImportDescriptor(0, 0, 0, 0, 0)]
    descriptors_len = 4 * 5 * len(descriptors)
    descriptors_end = descriptors_start + descriptors_len

    content = bytearray(descriptors_end)
    unknown_module_name_rva: Optional[int] = None
    for imp, ilt, desc in zip(tree, lookup_tables, descriptors):
        if isinstance(imp, _Import):
            desc.name = section_base_rva + len(content)
            content += imp.name.encode() + b"\0"
            for i, entry in enumerate(imp.entries):
                ilt[i] = section_base_rva + len(content)
                content += (
                    (entry.ordinal - 1).to_bytes(2, "little")
                    + entry.name.encode()
                    + b"\0"
                )
        else:
            if unknown_module_name_rva is None:
                unknown_module_name_rva = section_base_rva + len(content)
                content += b"?\0"
            desc.name = unknown_module_name_rva
            for i, _ in enumerate(imp.entries):
                ilt[i] = section_base_rva + len(content)
                content += b"v\x06?\0"

    content[:descriptors_start] = b"".join(
        e.to_bytes(ql.arch.pointersize, "little") for l in lookup_tables for e in l
    )
    content[descriptors_start:descriptors_end] = b"".join(map(bytes, descriptors))

    section = PE.Section(content, ".RAIJUU", 0xE0000060)
    section.virtual_size = ((len(content) // 0x1000) + 1) * 0x1000
    return (section, section_base_rva + descriptors_start, descriptors_len)


def dump(
    ql: Qiling,
    image_start: int,
    image_size: int,
    original_entrypoint: int,
    iat_start: Optional[int] = None,
    iat_size: Optional[int] = None,
) -> bytes:
    pe_data = ql.mem.read(image_start, image_size)
    dumped = PE.parse(pe_data, ql.targetname)
    dumped.optional_header.imagebase = image_start
    dumped.optional_header.addressof_entrypoint = original_entrypoint - image_start

    dumped.remove_all_libraries()

    import_table = dumped.data_directory(PE.DATA_DIRECTORY.IMPORT_TABLE)
    import_table.rva = 0
    import_table.size = 0

    iat = dumped.data_directory(PE.DATA_DIRECTORY.IAT)
    iat.rva = 0
    iat.size = 0

    zero_chunk = bytes(0x100)
    new_sections = []

    for i, section in enumerate(dumped.sections):
        section_data = ql.mem.read(
            image_start + section.virtual_address, section.virtual_size
        )
        for start in range(section.virtual_size - 0x100, section.size, -0x100):
            if section_data[start : start + 0x100] != zero_chunk:
                section_data = section_data[: start + 0x100]
                break
        else:
            section_data = section_data[: section.size]

        new = PE.Section(section_data, section.name, section.characteristics)
        new.virtual_size = section.virtual_size
        if i == 0:
            new.offset = section.offset
        new_sections.append(new)

    # Have to outline this loop to prevent a segfault
    for section in list(dumped.sections):
        dumped.remove(section, True)

    new_sections = [dumped.add_section(new) for new in new_sections]
    last_section = new_sections[-1]
    next_section_start = last_section.virtual_address + last_section.virtual_size

    if iat_start is None or iat_size is None:
        iat_start, iat_size = search_iat(ql, image_start, image_size)

    import_tree = import_tree_from_table(ql, image_start, iat_start, iat_size)
    import_section, import_rva, import_size = build_idata(
        ql, import_tree, next_section_start
    )
    dumped.add_section(import_section)
    import_table.rva = import_rva
    import_table.size = import_size

    builder = PE.Builder(dumped)
    builder.build()
    return builder.get_build()


__all__ = ["dump", "search_iat"]
