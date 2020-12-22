# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf

import binarylang, binarylang/plugins, bitstreams
import sequtils, sets

# Utilities
proc constructSet(start, finish, step: int): HashSet[uint32] =
  toSeq(countup(start, finish, step)).mapIt(it.uint32).toHashSet

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
  u8 {valid: e in {0x00, 0x30..0x5A, 0x70..0x91}}: lowByte
  u8 {valid: e in {0x00, 0x01, 0x02, 0x04}}: highByte

# 2.1 ShellLinkHeader
createParser(ShellLinkHeader, endian = l):
  u32: headerSize = 0x0000004C
  s: linkClsId =
    "\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
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

# 2.3.1 VolumeID
createParser(VolumeId, endian = l):
  u32 {valid: e > 0x10}: volumeIdSize
  u32 {valid: e in {0x00..0x06}}: driveType
  u32: driveSerialNumber
  u32 {valid: e < volumeIdSize}: volumeLabelOffset
  u32 {cond: volumeLabelOffset == 0x14, valid: e < volumeIdSize}:
    volumeLabelOffsetUnicode
  u8: data[volumeIdSize.int - p]

# 2.3.2 CommonNetworkRelativeLink
createParser(CommonNetworkRelativeLink, endian = l):
  u32 {valid: e >= 0x14}: commonNetworkRelativeLinkSize
  r1: validDevice
  r1: validNetType
  r30: _ = 0
  u32 {valid: e < commonNetworkRelativeLinkSize}: netNameOffset
  u32 {valid: e < commonNetworkRelativeLinkSize and (validDevice != 0 or
    e == 0)}: deviceNameOffset
  u32 {valid: (validNetType != 0 or e == 0) and e in
    constructSet(0x290000, 0x430000, 0x10000)}: networkProviderType
  u32 {cond: netNameOffset > 0x14, valid: e < commonNetworkRelativeLinkSize}:
    netNameOffsetUnicode
  u32 {cond: deviceNameOffset > 0x14, valid: e < commonNetworkRelativeLinkSize
    }: deviceNameOffsetUnicode
  s: netName
  s: deviceName
  s {cond: netNameOffset > 14}: netNameUnicode
  s {cond: deviceNameOffset > 14}: deviceNameUnicode

# 2.3 LinkInfo
createParser(LinkInfo, endian = l):
  u32: linkInfoSize
  u32 {valid: e == 0x1C or e >= 0x24}: linkInfoHeaderSize
  r1: volumeIdAndLocalBasePath
  r1: commonNetworkRelativeLinkAndPathSuffix
  r30: _ = 0
  u32 {valid: (volumeIdAndLocalBasePath != 0 or e == 0) and e < linkInfoSize}:
    volumeIdOffset
  u32 {valid: (volumeIdAndLocalBasePath != 0 or e == 0) and e < linkInfoSize}:
    localBasePathOffset
  u32 {valid: commonNetworkRelativeLinkAndPathSuffix != 0 or e == 0}:
    commonNetworkRelativeLinkOffset
  u32: commonPathSuffixOffset
  u32 {cond: linkInfoHeaderSize >= 0x24, valid: volumeIdAndLocalBasePath !=
    0 or e == 0}: localBasePathOffsetUnicode
  u32 {cond: linkInfoHeaderSize >= 0x24}: commonPathSuffixOffsetUnicode
  *VolumeId {cond: volumeIdAndLocalBasePath.bool}: volumeId
  s {cond: volumeIdAndLocalBasePath.bool}: localBasePath
  *CommonNetworkRelativeLink {cond: commonNetworkRelativeLinkAndPathSuffix.bool
    }: commonNetworkRelativeLink
  s: commonPathSuffix
  s {cond: volumeIdAndLocalBasePath.bool and linkInfoHeaderSize >= 0x24}:
    localBasePathUnicode
  s {cond: linkInfoHeaderSize >= 0x24}: commonPathSuffixUnicode

# 2.4 StringData
createParser(StringData, endian = l):
  u16: countCharacters
  u8: str[countCharacters]

createParser(ShellLink):
  *ShellLinkHeader: shellLinkHeader
  *LinkTargetIdList {cond: shellLinkHeader.linkFlags.hasLinkTargetIdList.bool}:
    linkTargetIdList
  *LinkInfo {cond: shellLinkHeader.linkFlags.hasLinkInfo.bool}: linkInfo
  *StringData {cond: shellLinkHeader.linkFlags.hasName.bool}: nameString
  *StringData {cond: shellLinkHeader.linkFlags.hasRelativePath.bool}:
    relativePath
  *StringData {cond: shellLinkHeader.linkFlags.hasWorkingDir.bool}: workingDir
  *StringData {cond: shellLinkHeader.linkFlags.hasArguments.bool}:
    commandLineArguments
  *StringData {cond: shellLinkHeader.linkFlags.hasIconLocation.bool}:
    iconLocation

export ShellLink