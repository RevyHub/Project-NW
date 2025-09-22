import os

NWA = r"""
  _  _      _ ___      __           _          
 | \| |_  _| | \ \    / /_ _ _ _ __| |___ _ _  
 | .` | || | | |\ \/\/ / _` | '_/ _` / -_) ' \ 
 |_|\_|\_,_|_|_| \_/\_/\__,_|_| \__,_\___|_||_|
"""

NWS = ("=" * 60)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


