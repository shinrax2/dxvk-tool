import PyInstaller.__main__

args_dxvk = [
    "--name=dxvk-tool",
    "--clean",
    "--onefile",
    "dxvk-tool.py"
]
args_d8vk = [
    "--name=d8vk-tool",
    "--clean",
    "--onefile",
    "d8vk-tool.py"
]

PyInstaller.__main__.run(dxvk_args)
PyInstaller.__main__.run(d8vk_args)
