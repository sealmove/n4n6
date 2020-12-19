# n4n6
## The dead-simple forensics framework

For the most part this repo aims to be a collection of parsers/serializers for file formats of forensics value. Each module in `parsers` directory exposes a single `tuple` of a `get` and a `put` procedure.

The rest of the project is about presenting the information in various ways, from low-level (data tree) to high-level (domain specific, ex. dates in ISO 8601).

The parsers are written in a declarative manner using [binarylang](https://github.com/sealmove/binarylang). This repo is my personal first attempt to dogfood it.

## Toolkits
- Windows
  - **`wlf`**: Shell Link Files (Shortcuts)