# Serious Sam Fusion Achievement Enabler

## How to use
Download Sam2017_ModAchievements.exe from the latest releases.
>| 1st Method: |
>|:- |
>| Put the `Sam2017_ModAchievements.exe` inside the game folder's `/Bin/x64/` folder right besides the `Sam2017_Unrestricted.exe` and launch `Sam2017_ModAchievements.exe`. |
>
>| 2nd Method: |
>|:- |
>| Launch `Sam2017_Unrestricted.exe` or modded Fusion through Steam and then launch `Sam2017_ModAchievements.exe`. |

## Launcher information
If the game quits/crashes - you don't need to relaunch the achievement enabler, just launch the modded Fusion executable.

If the game restarts - no need to worry, the achievement enabler will automatically hook itself.

## How does it work
The launcher finds a function which the game uses for awarding achievements, and rewrites the function to call Steamworks API to award achievements, skipping checks for if the game is modded or uses cheats.

## Project information
It works and you won't get banned for using this in a multiplayer lobby.

This possibly could be rewritten to just modify a single jump instruction within deeper levels of the function that awards achievements. But I couldn't bother doing run-time analysis of the function, but I might do that at some point by setting a breakpoint on SteamUserStats and stepping through the code. 

Project uses https://github.com/Zer0Mem0ry/SignatureScanner for the scanner.