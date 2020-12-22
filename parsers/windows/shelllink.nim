# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf

import binarylang, binarylang/plugins, bitstreams

# 2.1.1 LinkFlags
createParser(LinkFlags, bitEndian = r):
  1: hasLinkTargetIdList
  1: hasLinkInfo
  1: hasName
  1: hasRelativePath
  1: hasWorkingDir
  1: hasArguments
  1: hasIconLocation
  1: isUnicode
  1: forceNoLinkInfo
  1: hasExpString
  1: runInSeparateProcess
  1: unused1
  1: hasDarwinId
  1: runAsUser
  1: hasExpIcon
  1: noPidlAlias
  1: unused2
  1: runWithShimLayer
  1: forceNoLinkTrack
  1: enableTargetMetadata
  1: disableLinkPathTracking
  1: disableKnownFolderTracking
  1: disableKnownFolderAlias
  1: allowLinkToLink
  1: unaliasOnSave
  1: preferEnvironmentPath
  1: keepLocalIdListForUNCTarget
  5: _

# 2.1.2 FileAttributesFlags
createParser(FileAttributesFlags, bitEndian = r):
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
  17: _

# 2.1.3 HotKeyFlags
createParser(HotKeyFlags):
  u8: lowByte
  u8: highByte

# 2.1 ShellLinkHeader
createParser(ShellLinkHeader, endian = l):
  u32: headerSize = 0x0000004C
  s: linkClsId = "\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
  *LinkFlags: linkFlags
  *FileAttributesFlags: fileAttributes
  u64: creationTime
  u64: accessTime
  u64: writeTime
  u32: fileSize
  u32: iconIndex
  u32: showCommand
  *HotKeyFlags: hotKey
  16: reserved1 = 0
  32: reserved2 = 0
  32: reserved3 = 0

# 2.2.2 ItemID
createParser(ItemId, endian = l):
  u16: itemIdSize
  u8: data[itemIdSize - 2]

# 2.2.1 IDList
createParser(IdList):
  *ItemId: {itemIdList}
  u16: terminalId = 0

# 2.2 LinkTargetIDList
createParser(LinkTargetIdList, endian = l):
  u16: idListSize
  *IdList: idList(idListSize)

createParser(ShellLink):
  *ShellLinkHeader: shellLinkHeader
  *LinkTargetIdList {cond: shellLinkHeader.linkFlags.hasLinkTargetIdList.bool}: linkTargetIdList

export ShellLink