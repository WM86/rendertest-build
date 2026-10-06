"""往 TinecmaTools 源码（Tinenc/GraphicsDebugger @6aca0a0d）的 D3D12 driver 里插诊断日志。

目的只有一个：搞清 `D3D12CreateDevice` 这条钩子到底有没有被调用。
那份源码里成功的路径本来就有 RDCLOG，安静的路径全是 RDCDEBUG，
所以「日志里什么都没有」既可能是钩子没挂上，也可能是游戏没走这个导出。
在必经之路插两行，就能把两种情况分开。

用法: python diag.py <src-root>
"""
import os
import sys


def emit(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()


RULES = [
    (
        "renderdoc/driver/d3d12/d3d12_hooks.cpp",
        'RDCLOG("Registering D3D12 hooks");',
        'RDCLOG("Registering D3D12 hooks [diag: d3d12.dll=%p d3dcompiler=%p]",\n'
        '            (void *)GetModuleHandleA("d3d12.dll"), (void *)GetD3DCompiler());',
        "注册时机：d3d12.dll 是否已在进程里",
    ),
    (
        "renderdoc/driver/d3d12/d3d12_hooks.cpp",
        "    PFN_D3D12_CREATE_DEVICE createFunc = d3d12hooks.CreateDevice();",
        '    RDCLOG("[diag] D3D12CreateDevice_hook ENTER (orig=%p)",\n'
        "            (void *)d3d12hooks.CreateDevice());\n"
        "\n"
        "    PFN_D3D12_CREATE_DEVICE createFunc = d3d12hooks.CreateDevice();",
        "钩子入口：被调用过就一定有这一行",
    ),
]


def main():
    if len(sys.argv) < 2:
        emit("usage: python diag.py <src-root>")
        return 1

    root = sys.argv[1]
    ok = miss = 0

    for rel, old, new, desc in RULES:
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(path):
            emit("MISSING  " + rel)
            miss += 1
            continue

        with open(path, "rb") as f:
            data = f.read()

        plain = old.encode("utf-8")
        plain_new = new.encode("utf-8")
        crlf = plain.replace(b"\n", b"\r\n")
        crlf_new = plain_new.replace(b"\n", b"\r\n")

        if data.count(plain):
            data = data.replace(plain, plain_new)
            n = 1
        elif data.count(crlf):
            data = data.replace(crlf, crlf_new)
            n = 1
        else:
            emit("NOHIT    %s  <- %s" % (rel, desc))
            miss += 1
            continue

        with open(path, "wb") as f:
            f.write(data)
        emit("OK       %-52s (%s)" % (rel, desc))
        ok += 1

    emit("")
    emit("applied=%d missed=%d" % (ok, miss))
    return 0 if miss == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
