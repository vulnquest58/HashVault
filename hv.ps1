# HashVault CLI shortcut — run from project root
# Usage: .\hv.ps1 analyze --list-ops
#        .\hv.ps1 crack 5f4dcc3b5aa765d61d8327deb882cf99
#        .\hv.ps1 identify 5f4dcc3b5aa765d61d8327deb882cf99

param([Parameter(ValueFromRemainingArguments=$true)] [string[]]$args)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python -m hashvault @args
