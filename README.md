# n4n6
## Edit binary data in human readable format!

Collection of parsers written in [binarylang](https://github.com/sealmove/binarylang) along with a cli tool for encoding/decoding binary files to/from human readable formats.

### Parsers:
- Windows
  - Shell Link (Shortcut)
  - Shell Item (Shellbag)

### CLI
Syntax:
```sh
n4n6 <encode/decode> <format> <parser alias> <binary file> <input/output file>
```

Example:
```sh
n4n6 encode json winshelllink myShortcut.lnk out.json
n4n6 decode json winshelllink myNewShortcut.lnk in.json
```

Supported formats:
- json

Aliases:
- winshelllink