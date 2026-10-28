"""
UI color themes, ASCII Banner, and Prompt Toolkit styles for HashVault interactive mode.
"""
from prompt_toolkit.styles import Style

BANNER_TEXT = r"""[bold cyan]
  ___ ___               .__  ____   ____            .__   __   
 /   |   \_____    _____|  |_\   \ /   /____   __ __|  |_/  |_ 
/    ~    \__  \  /  ___/  |  \   Y   /\__  \ |  |  \  |\   __\
\    Y    // __ \_\___ \|   Y  \     /  / __ \|  |  /  |_|  |  
 \___|_  /(____  /____  >___|  /\___/  (____  /____/|____/__|  
       \/      \/     \/     \/             \/                 
[/bold cyan]
[bold white]   HashVault — Security Auditing & Password Assessment Tool v2.0[/bold white]
[dim]   Ethical & Legal Audit Use Only | High-Performance Multi-Tool Core[/dim]
"""

hashvault_style = Style.from_dict(
    {
        "prompt": "bold #00aaff",
        "username": "bold #ffaa00",
        "command": "#55ff55",
        "option": "#ffff55",
        "hash": "#ff55ff",
        "status.success": "#00ff00 bold",
        "status.failed": "#ff0000 bold",
        "status.warning": "#ffaa00",
    }
)
