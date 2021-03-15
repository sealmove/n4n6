# n4n6
## Edit binary data in json!
A collection of parsers written in [binarylang](https://github.com/sealmove/binarylang) along with a tool for exporting/importing parsed data to/from json.

### Parsers:
- Windows
  - Shell Link (Shortcut)
  - Shell Item (Shellbag)
  - Prefetch

### CLI
Syntax:
```sh
n4n6 <encode/decode> <parser alias> <binary> <json>
```

Example:
```sh
n4n6 encode winshelllink myShortcut.lnk out.json
n4n6 decode winshelllink myNewShortcut.lnk in.json
```

Aliases:
- winshelllink
- winprefetch
- winpe