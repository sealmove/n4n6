# n4n6
## The dead-simple forensics framework

For the most part this repo aims to be a collection of parsers/serializers for file formats of forensics value.

Each module in `parsers` directory exposes a single `tuple` of a `get` and a `put` procedure. These are written in a _mostly_ declarative manner using (binaryparse)[https://github.com/PMunch/binaryparse] library.

n4n6 module is currently a simple tool that takes 2 cli arguments: the format and the path of a file to analyze. The analysis is format-specific and some valuable forensics information is printed on `stdout`.

In the future the plan is to provide a simple interface through which one not only can view key information parsed from files, but can also edit it in the most human-friendly way depending on the domain (for example edit dates as in ISO 8601 format), and then serialize it back automatically.

## Toolkits
- Windows
  - **`wlf`**: Shell Link Files (Shortcuts)