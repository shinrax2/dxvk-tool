import PyInstaller.__main__

dxvk_args = [
    "--name=dxvk-tool",
    "--clean",
    "--onefile",
    "dxvk-tool.py"
]
d8vk_args = [
    "--name=d8vk-tool",
    "--clean",
    "--onefile",
    "d8vk-tool.py"
]

PyInstaller.__main__.run(dxvk_args)
PyInstaller.__main__.run(d8vk_args)
