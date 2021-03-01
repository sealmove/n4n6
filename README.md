# n4n6
## Edit binary data in json!

The goal of this project is to provide a generic method for transforming a binary file to a human friendly json format, suitable for editing, which can then be transformed back to the binary format.

![Data flow](flow.svg)

This is a piecewise project consisting of 3 distinct functionalities:
- Collection of parsers written in [binarylang](https://github.com/sealmove/binarylang)
- Collection of json transformers
- CLI tool for using the above conventiently

### Parsers:
- Windows
  - Shell Link (Shortcut)
  - Shell Item (Shellbag)
  - Prefetch

### CLI
Syntax:
```sh
n4n6 <encode/decode> <parser alias> <binary> <json> [--raw|-r]
# json refers to the human-readable format unless option raw is specified
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

### Note
The transformation step is not yet implemented, therefore the json output comes directely from the parser.