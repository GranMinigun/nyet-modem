# nyet-modem
Serial port communications to TCP socket wrapper for NWC's Heroes of Might and Magic.

## Usage
Drop `netapi32.dll` and `nyet-modem.cfg` to the game's installation folder, then set options in the configuration file as needed. Supported options and values are:
- `mode`: determines whether you'll be hosting a game session or connecting to server; defaults to `client`, can be set to `server`.
- `listen_address`: IP address to listen on, used solely by server; defaults to `0.0.0.0` (all interfaces).
- `connect_address`: IP address to connect to, used solely by client; set it to server's address you're going to connect to.
- `port`: port to listen on or connect to; defaults to `52325`, should be the same on both client and server.

In game, go to New (or Load) Game => Multi-player Game => Direct Connect => Host or Guest, depending on who's going to create game session. COM-port number and baud rate do not matter.

## Compatibility
Confirmed to work with Heroes of Might and Magic, version 1.1, original English and Russian language releases. Version 1.2 from Compendium should work as well. Mixing game releases and versions is not recommended.

Wrapper works on Windows systems from XP to 10, and also through Wine (don't forget to set DLL override).

## Building
### Windows
Use included solution file in Visual Studio. Retarget if needed.

Visual Studio Code should suffice as well, but no configuration is included.

### Linux
Cross-compiling with MinGW currently isn't supported.

## Third-party
Uses SubHook by Zeex, licensed under the 2-clause BSD license: https://github.com/Zeex/subhook
