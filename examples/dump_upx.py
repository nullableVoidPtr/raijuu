from qiling import Qiling

import raijuu

ql = Qiling(["./rootfs/x8664_windows/x8664_file_upx.exe"], "./rootfs/x8664_windows")

pe_image = ql.loader.images[0]
base = pe_image.base
OEP = base + 0x13E0

ql.hook_address(raijuu.dump_hook, OEP)
ql.run()
if raijuu.result:
    with open("./rootfs/x8664_windows/dumped.exe", "wb") as f:
        f.write(raijuu.result)
