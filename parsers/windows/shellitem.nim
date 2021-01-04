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

# 6.4 Extension block 0xbeef0003
createParser(ExtensionBlock0xbeef0003):
  u16: size
  u16: version
  u32: signature = 0xBEEF0003'u32
  b16: shellFolderId
  u16: offset

createParser(FatTime, endian = l):
  u16: low
  u16: high

createParser(ClsId):
  lu32: part1
  lu16: part2
  lu16: part3
  bu16: part4
  u8: part5[6]

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
createParser(RootFolderShellItem):
  u8: sortIndex
  *ClsId: shellFolderId

# 3.3 Volume shell item
createParser(VolumeShellItem, clsTypeId: byte):
  u8 {cond: bool(clsTypeId and 0x1)}: flags

# 3.4 File entry shell item
createParser(FileEntryShellItem, endian = l, clsTypeId: byte):
  8: _ = 0
  u32: fileSize
  *FatTime: writeTime
  *FileAttributesFlagsLow: fileAttributeFlags
  s {cond: (clsTypeId and 0x04) == 0}: primaryName
  u16 {cond: (clsTypeId and 0x04) == 1}: primaryNameUnicode{e == 0}

# 2.1 Shell Item
type ShellItemTy* = ref object
  case code*: byte
  of 0x10: rootFolder*: typeGetter(RootFolderShellItem)
  of 0x20: volume*: typeGetter(VolumeShellItem)
  of 0x30: fileEntry*: typeGetter(FileEntryShellItem)
  else: discard
proc shellItemGet(s: BitStream, code: byte): ShellItemTy =
  result = ShellItemTy(code: code)
  case code
  of 0x10: result.rootFolder = RootFolderShellItem.get(s)
  of 0x20: result.volume = VolumeShellItem.get(s, code)
  of 0x30: result.fileEntry = FileEntryShellItem.get(s, code)
  else: discard
proc shellItemPut(s: BitStream, input: ShellItemTy, code: byte) =
  case input.code
  of 0x10: RootFolderShellItem.put(s, input.rootFolder)
  of 0x20: VolumeShellItem.put(s, input.volume, code)
  of 0x30: FileEntryShellItem.put(s, input.fileEntry, code)
  else: discard
let ShellItemData = (get: shellItemGet, put: shellItemPut)

createParser(ShellItem, endian = l):
  u16: size
  u8: clsTypeId
  *ShellItemData(clsTypeId and 0x70): data(size - 3)

export FileAttributesFlags, ClsId, FatTime, ShellItem