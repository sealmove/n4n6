# https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc

import binarylang, binarylang/plugins, bitstreams

createParser(FileAttributesFlagsLow, bitEndian = r):
  1: readonly
  1: hidden
  1: system
  1: reserved1 = 0
  1: directory
  1: archive
  1: reserved2 = 0
  1: normal
  1: temporary
  1: sparseFile
  1: reparsePoint
  1: compressed
  1: offline
  1: notContentIndexed
  1: encrypted
  1: integrityStream

createParser(FileAttributesFlagsHigh, bitEndian = r):
  1: virtual
  1: noScrubData
  14: _

createParser(FileAttributesFlags):
  *FileAttributesFlagsLow: low
  *FileAttributesFlagsHigh: high

# 3.2 Root folder shell item
createParser(RootFolderShellItem):
  u8: sortIndex
  16: shellFolderId

# 3.3 Volume shell item
createParser(VolumeShellItem, clsId: byte):
  u8 {cond: bool(clsId and 0x1)}: flags

# 3.4 File entry shell item
createParser(FileEntryShellItem, endian = l, clsId: byte):
  8: _ = 0
  u32: fileSize
  32: writeTime
  *FileAttributesFlagsLow: fileAttributeFlags
  u16: primaryName{e == 0}
  u16: secondaryName{e == 0}

# 2.1 Shell Item
createParser(ShellItemData):
  u8: clsId

export FileAttributesFlags