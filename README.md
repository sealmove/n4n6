# n4n6
## The dead-simple forensics framework

For the most part this repo aims to be a collection of parsers/serializers for file formats of forensics value. Each module in `parsers` directory exposes a single `tuple` of a `get` and a `put` procedure. These are written in a _mostly_ declarative manner using [binaryparse](https://github.com/PMunch/binaryparse) library.

The rest of the project is about presenting the information and allowing the user to edit it in various ways, from low-level (editing the bits and bytes directly) to high-level (edit in domain specific format, ex. dates in ISO 8601).

## Status
The first part (writting the parsers) will likely be completed relatively soon. The second part about presentation will take much longer, and for now only tree dump and simple domain-specific printing of key information will be implemented. Try running the n4n6 modules and see what it can do.

## Toolkits
- Windows
  - **`wlf`**: Shell Link Files (Shortcuts)