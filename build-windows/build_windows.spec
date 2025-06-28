# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['../QR-gui.py'],
    pathex=[],
    binaries=[],
    datas=[('../assets', 'assets')],
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'threading',
        'os',
        'time',
        'json',
        'base64',
        'pathlib',
        'typing',
        'hashlib',
        'platform',
        'secrets',
        'struct',
        'winshell',
        'win32con',
        'Crypto.Random',
        'Crypto.Cipher.AES'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='QR-AES-256',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='../atom.png'  # Use PNG for Windows build
)
