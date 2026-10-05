"""
给 RenderDoc v1.x 打「绕 CrashSight 检测」的特征补丁。
用法: python patch.py <renderdoc 源码根目录>

改动内容见 workspace 里那份笔记：把 RenderDoc 的牌子相关符号、路径、
内核对象名、注册表路径、UI 文本全部改成 rendertest*，让检测拿不到 RenderDoc 特征。

文件按二进制方式处理，避免踩到编码坑（renderdoc.rc 里有 Latin-1 的版权符）。
"""
import os
import sys

# (相对路径, 旧, 新)
RULES = [
    # 最核心：DLL 用来判断「当前是不是 replay 环境」的导出符号
    ("renderdoc/api/replay/renderdoc_replay.h",
     "renderdoc__replay__marker", "rendertest__replay__marker"),

    # 进程创建与注入的路径
    ("renderdoc/os/win32/win32_process.cpp", "renderdoccmd.exe", "rendertestcmd.exe"),
    ("renderdoc/os/win32/win32_process.cpp", "renderdocshim64.dll", "rendertestshim64.dll"),
    ("renderdoc/os/win32/win32_process.cpp", "renderdocshim32.dll", "rendertestshim32.dll"),

    # 进程白名单，避免注入到自己身上
    ("renderdoc/os/win32/sys_win32_hooks.cpp", "renderdoccmd.exe", "rendertestcmd.exe"),
    ("renderdoc/os/win32/sys_win32_hooks.cpp", "qrenderdoc.exe", "qrendertest.exe"),

    # 崩溃处理里的内核对象名
    ("renderdoccmd/renderdoccmd_win32.cpp", "RENDERDOC_CRASHHANDLE", "RENDERTEST_CRASHHANDLE"),
    ("renderdoccmd/renderdoccmd_win32.cpp", "renderdoc.dll", "rendertest.dll"),
    ("renderdoc/core/crash_handler.h", "RenderDocBreakpadServer", "RenderTestBreakpadServer"),
    ("renderdoc/core/crash_handler.h", 'L"RenderDoc\\\\', 'L"RenderTest\\\\'),

    # 注册表 / 日志路径
    ("renderdoc/os/win32/win32_stringio.cpp", "qrenderdoc.exe", "qrendertest.exe"),
    ("renderdoc/os/win32/win32_stringio.cpp", "RenderDoc.RDCCapture.1", "RenderTest.RDCCapture.1"),
    ("renderdoc/os/win32/win32_stringio.cpp", 'L"RenderDoc\\\\', 'L"RenderTest\\\\'),

    # OpenGL 窗口类名
    ("renderdoc/driver/gl/wgl_platform.cpp", "renderdocGLclass", "rendertestGLclass"),

    # 全局钩子的共享内存名
    ("renderdocshim/renderdocshim.h", "RenderDocGlobalHookData64", "RenderTestGlobalHookData64"),
    ("renderdocshim/renderdocshim.h", "RenderDocGlobalHookData32", "RenderTestGlobalHookData32"),

    # 资源文件
    ("renderdoc/data/renderdoc.rc", "Core DLL for RenderDoc", "Core DLL for RenderTest"),
    ("renderdoc/data/renderdoc.rc", '"ProductName", "RenderDoc"', '"ProductName", "RenderTest"'),

    # UI 层
    ("qrenderdoc/renderdocui_stub.cpp", "qrenderdoc.exe", "qrendertest.exe"),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"QRenderDoc initialising."', '"QRenderTest initialising."'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"Qt UI for RenderDoc"', '"Qt UI for RenderTest"'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"QRenderDoc v%s"', '"QRenderTest v%s"'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"qrenderdoc"', '"qrendertest"'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"QRenderDoc"', '"QRenderTest"'),
    ("qrenderdoc/Windows/MainWindow.cpp", '"RenderDoc "', '"RenderTest "'),
]


def main():
    if len(sys.argv) < 2:
        print("用法: python patch.py <renderdoc 源码根目录>")
        return 1
    root = sys.argv[1]

    hit = miss = 0
    for rel, old, new in RULES:
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(path):
            print(f"缺文件  {rel}")
            miss += 1
            continue
        with open(path, "rb") as f:
            data = f.read()
        ob = old.encode("latin-1")
        nb = new.encode("latin-1")
        n = data.count(ob)
        if n == 0:
            print(f"未命中  {rel}  <- {old[:44]}")
            miss += 1
            continue
        with open(path, "wb") as f:
            f.write(data.replace(ob, nb))
        print(f"OK      {rel}  {old[:44]}  x{n}")
        hit += n

    print(f"\n共替换 {hit} 处，未命中 {miss} 项")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
