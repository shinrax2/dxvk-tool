# dxvk-tool
tool to install, update or remove dxvk installations for windows

# features
- easy updating of all your dxvk installations
- automatic detection of used DXVK files (d3d9, d3d10core, d3d11, dxgi) and bitness based on game executable
- caching of DXVK versions for faster installation

# requirements
- python3
- requests
- pefile

install with ```python3 -m pip install -r requirements.txt```

# usage
start dxvk-tool with `python3 dxvk-tool.py`
