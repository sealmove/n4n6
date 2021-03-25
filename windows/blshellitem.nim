# https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc

import binarylang, binarylang/plugins

createParser(*fileAttributesFlagsLow, bitEndian = r):
  1: *readonly
  1: *hidden
  1: *system
  1: *reserved1 = 0
  1: *directory
  1: *archive
  1: *reserved2 = 0
  1: *normal
  1: *temporary
  1: *sparseFile
  1: *reparsePoint
  1: *compressed
  1: *offline
  1: *notContentIndexed
  1: *encrypted
  1: *integrityStream

createParser(*fileAttributesFlagsHigh, bitEndian = r):
  1: *virtual
  1: *noScrubData
  14: _

createParser(*fileAttributesFlags):
  *fileAttributesFlagsLow: *low
  *fileAttributesFlagsHigh: *high

# 6.4 Extension block 0xbeef0003
createParser(*extensionBlock0xbeef0003):
  u16: *size
  u16: *version
  u32: *signature = 0xBEEF0003'u32
  b16: *shellFolderId
  u16: *offset

createParser(*fatTime, endian = l):
  u16: *low
  u16: *high

createParser(*clsId):
  lu32: *part1
  lu16: *part2
  lu16: *part3
  bu16: *part4
  u8: *part5[6]

type SortIndex* = enum
  siInternetExplorer = (0x00, "Internet Explorer")
  siLibraries = (0x42, "Libraries")
  siUsers = (0x44, "Users")
  siMyDocuments = (0x48, "My Documents")
  siMyComputer = (0x50, "My Computer")
  siNetwork = (0x58, "Network")
  siRecycleBin = (0x60, "Recycle Bin")
  siInternetExplorer2 = (0x68, "Internet Explorer")
  siMyGames = (0x80, "My Games")

# 3.2 Root folder shell item
createParser(*rootFolderShellItem):
  u8: *sortIndex
  *clsId: *shellFolderId

# 3.3 Volume shell item
createParser(*volumeShellItem, clsTypeId: byte):
  u8 {cond: bool(clsTypeId and 0x1)}: *flags

# 3.4 File entry shell item
createParser(*fileEntryShellItem, endian = l, clsTypeId: byte):
  8: _ = 0
  u32: *fileSize
  *fatTime: *writeTime
  *fileAttributesFlagsLow: *fileAttributeFlags
  s {cond: (clsTypeId and 0x04) == 0}: *primaryName
  u16 {cond: (clsTypeId and 0x04) == 1}: *primaryNameUnicode{_ == 0}

# 2.1 Shell Item
createVariantParser(*shellItemData, *code: byte):
  (0x10): *rootFolderShellItem: *rootFolder
  (0x20): *volumeShellItem(code): *volume
  (0x30): *fileEntryShellItem(code): *fileEntry
  _: nil

createParser(*shellItem, endian = l):
  u16: *size
  u8: *clsTypeId
  *shellItemData(clsTypeId and 0x70): *data(size - 3)