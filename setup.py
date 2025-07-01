"""
Setup script para crear aplicación macOS .app con py2app
"""

import sys

from setuptools import setup

APP = ["QuantumARK.py"]
DATA_FILES = [
    (
        "assets",
        ["assets/atom.png", "assets/atom.icns", "assets/Quattrocento-Regular.ttf"],
    ),
]

OPTIONS = {
    "argv_emulation": True,
    "plist": {
        "CFBundleName": "QuantumARK",
        "CFBundleDisplayName": "QuantumARK - Quantum-Resistant File Encryptor",
        "CFBundleIdentifier": "com.maubennetts.quantumark",
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleInfoDictionaryVersion": "6.0",
        "NSHumanReadableCopyright": "Copyright © 2025 MauBennetts. All rights reserved.",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "10.12.0",
        "CFBundleDocumentTypes": [
            {
                "CFBundleTypeName": "QR-AES-256 Encrypted File",
                "CFBundleTypeExtensions": ["qr256"],
                "CFBundleTypeRole": "Editor",
                "CFBundleTypeIconFile": "atom.icns",
            }
        ],
    },
    "packages": [
        "tkinter",
        "cryptography",
        "hashlib",
        "secrets",
        "threading",
        "json",
        "base64",
        "jaraco",
        "jaraco.text",
        "jaraco.context",
        "jaraco.functools",
    ],
    "includes": [
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "tkinter.scrolledtext",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.hashes",
        "cryptography.hazmat.primitives.kdf.pbkdf2",
        "cryptography.hazmat.backends",
        "hashlib",
        "secrets",
        "threading",
        "json",
        "base64",
        "struct",
        "pathlib",
        "platform",
        "time",
        "os",
        "jaraco",
        "jaraco.text",
        "jaraco.context",
        "jaraco.functools",
    ],
    "excludes": ["matplotlib", "numpy", "scipy"],
    "iconfile": "assets/atom.icns",
    "resources": ["assets/"],
}

setup(
    app=APP,
    name="QuantumARK",
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
    python_requires=">=3.6",
)
