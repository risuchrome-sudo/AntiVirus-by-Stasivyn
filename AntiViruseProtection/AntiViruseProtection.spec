# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
from PyInstaller.utils.hooks import collect_dynamic_libs

PROJECT_ROOT = Path(SPECPATH).resolve()
DATA_DIRS = [
    (PROJECT_ROOT / "engine" / "Updater" / "data", "engine/Updater/data"),
    (PROJECT_ROOT / "engine" / "YARA" / "rules", "engine/YARA/rules"),
    (PROJECT_ROOT / "engine" / "quarantine" / "files", "engine/quarantine/files"),
]

datas = []
for source_dir, destination_dir in DATA_DIRS:
    if source_dir.is_dir():
        for source_file in source_dir.rglob("*"):
            if source_file.is_file():
                relative_parent = source_file.parent.relative_to(source_dir)
                target_dir = Path(destination_dir) / relative_parent
                datas.append((str(source_file), target_dir.as_posix()))

binaries = collect_dynamic_libs("yara")

a = Analysis(
    [str(PROJECT_ROOT / "interface" / "interface.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=["yara"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AntiViruseProtection",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="AntiViruseProtection",
)
