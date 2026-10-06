"""
Patch RenderDoc v1.x with the "avoid CrashSight detection" signature changes.
Usage: python patch.py <renderdoc source root>

Everything RenderDoc-branded (exported symbols, paths, kernel object names,
registry keys, UI strings) is renamed to rendertest*, so the anti-cheat's
signature scan no longer matches.

Files are handled as raw bytes on purpose: renderdoc.rc contains a Latin-1
copyright sign, and text-mode IO with the wrong codec would corrupt it.
"""
import os
import sys

# (relative path, old, new)
RULES = [
    # Core: the exported symbol the DLL uses to tell "am I inside the replay app"
    ("renderdoc/api/replay/renderdoc_replay.h",
     "renderdoc__replay__marker", "rendertest__replay__marker"),

    # ...and the other half of that check: the loader looks the marker up by
    # runtime name built from RDOC_BASE_NAME. That macro is pinned to
    # "rendertest" in renderdoc.vcxproj further down, so the name built here and
    # the literal marker exported above end up the same.
    ("renderdoc/os/win32/win32_libentry.cpp",
     'STRINGIZE(RDOC_BASE_NAME) "__replay__marker"', '"rendertest" "__replay__marker"'),

    # The core DLL itself: renderdoc.dll -> rendertest.dll. RDOC_BASE_NAME is
    # what the module name, replay marker, log prefixes and crash handler are all
    # built from, so pin it explicitly instead of letting it follow
    # $(ProjectName); ProjectName and TargetName move with it so the output file,
    # import library and Vulkan layer JSON all come out as rendertest.
    ("renderdoc/renderdoc.vcxproj",
     "<ProjectName>renderdoc</ProjectName>",
     "<ProjectName>rendertest</ProjectName>\r\n    <TargetName>rendertest</TargetName>"),
    ("renderdoc/renderdoc.vcxproj",
     "RDOC_BASE_NAME=$(ProjectName)", "RDOC_BASE_NAME=rendertest"),

    # Process creation / injection paths
    ("renderdoc/os/win32/win32_process.cpp", "renderdoccmd.exe", "rendertestcmd.exe"),
    ("renderdoc/os/win32/win32_process.cpp", "renderdocshim64.dll", "rendertestshim64.dll"),
    ("renderdoc/os/win32/win32_process.cpp", "renderdocshim32.dll", "rendertestshim32.dll"),

    # Process whitelist so we never inject into ourselves
    ("renderdoc/os/win32/sys_win32_hooks.cpp", "renderdoccmd.exe", "rendertestcmd.exe"),
    ("renderdoc/os/win32/sys_win32_hooks.cpp", "qrenderdoc.exe", "qrendertest.exe"),

    # Crash handling kernel objects
    ("renderdoccmd/renderdoccmd_win32.cpp", "RENDERDOC_CRASHHANDLE", "RENDERTEST_CRASHHANDLE"),
    ("renderdoccmd/renderdoccmd_win32.cpp", "renderdoc.dll", "rendertest.dll"),
    ("renderdoc/core/crash_handler.h", "RenderDocBreakpadServer", "RenderTestBreakpadServer"),
    ("renderdoc/core/crash_handler.h", 'L"RenderDoc\\\\', 'L"RenderTest\\\\'),

    # Registry / log paths
    ("renderdoc/os/win32/win32_stringio.cpp", "qrenderdoc.exe", "qrendertest.exe"),
    ("renderdoc/os/win32/win32_stringio.cpp", "RenderDoc.RDCCapture.1", "RenderTest.RDCCapture.1"),
    ("renderdoc/os/win32/win32_stringio.cpp", 'L"RenderDoc\\\\', 'L"RenderTest\\\\'),

    # OpenGL window class
    ("renderdoc/driver/gl/wgl_platform.cpp", "renderdocGLclass", "rendertestGLclass"),

    # Global hook shared memory
    ("renderdocshim/renderdocshim.h", "RenderDocGlobalHookData64", "RenderTestGlobalHookData64"),
    ("renderdocshim/renderdocshim.h", "RenderDocGlobalHookData32", "RenderTestGlobalHookData32"),

    # Resource file - the DLL name shows up in two version fields
    ("renderdoc/data/renderdoc.rc", "Core DLL for RenderDoc", "Core DLL for RenderTest"),
    ("renderdoc/data/renderdoc.rc", '"ProductName", "RenderDoc"', '"ProductName", "RenderTest"'),
    ("renderdoc/data/renderdoc.rc", '"InternalName", "renderdoc"', '"InternalName", "rendertest"'),
    ("renderdoc/data/renderdoc.rc", '"OriginalFilename", "renderdoc.dll"',
     '"OriginalFilename", "rendertest.dll"'),

    # Qt UI layer
    ("qrenderdoc/renderdocui_stub.cpp", "qrenderdoc.exe", "qrendertest.exe"),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"QRenderDoc initialising."', '"QRenderTest initialising."'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"Qt UI for RenderDoc"', '"Qt UI for RenderTest"'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"QRenderDoc v%s"', '"QRenderTest v%s"'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"qrenderdoc"', '"qrendertest"'),
    ("qrenderdoc/Code/qrenderdoc.cpp", '"QRenderDoc"', '"QRenderTest"'),
    ("qrenderdoc/Windows/MainWindow.cpp", '"RenderDoc "', '"RenderTest "'),

    # Last literal reference to the core DLL by name
    ("qrenderdoc/Windows/Dialogs/UpdateDialog.cpp", '"renderdoc.dll"', '"rendertest.dll"'),
]


def emit(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def main():
    if len(sys.argv) < 2:
        emit("usage: python patch.py <renderdoc-source-root>")
        return 1
    root = sys.argv[1]

    hit = miss = 0
    for rel, old, new in RULES:
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(path):
            emit("MISSING  " + rel)
            miss += 1
            continue
        with open(path, "rb") as f:
            data = f.read()
        ob = old.encode("latin-1")
        nb = new.encode("latin-1")
        n = data.count(ob)
        if n == 0:
            emit("NOHIT    " + rel + "  <- " + old[:44])
            miss += 1
            continue
        with open(path, "wb") as f:
            f.write(data.replace(ob, nb))
        emit("OK       " + rel + "  " + old[:44] + "  x" + str(n))
        hit += n

    emit("")
    emit("replaced=%d  missed=%d" % (hit, miss))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
