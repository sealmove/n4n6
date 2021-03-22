# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf

import shellitem
import binarylang, binarylang/plugins
import sequtils, sets

# Utilities
proc constructSet(start, finish, step: int): HashSet[uint32] =
  toSeq(countup(start, finish, step)).mapIt(it.uint32).toHashSet

# 2.1.1 LinkFlags
createParser(linkFlags, bitEndian = r):
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

# 2.1.3 HotKeyFlags
createParser(hotKeyFlags):
  u8 {valid: _ in {0x00, 0x30..0x5A, 0x70..0x91}}: lowByte
  u8 {valid: _ in {0x00, 0x01, 0x02, 0x04}}: highByte

# 2.1 ShellLinkHeader
createParser(shellLinkHeader, endian = l):
  u32: headerSize = 0x0000004C
  s: linkClsId =
    "\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
  *linkFlags: linkFlags
  *fileAttributesFlags: fileAttributes
  64: creationTime
  64: accessTime
  64: writeTime
  u32: fileSize
  u32: iconIndex
  u32: showCommand
  *hotKeyFlags: hotKey
  16: reserved1 = 0
  32: reserved2 = 0
  32: reserved3 = 0

# 2.2.1 IDList
createParser(idList):
  *shellItem: {itemIdList}
  u16: terminalId = 0

# 2.2 LinkTargetIDList
createParser(linkTargetIdList, endian = l):
  u16: idListSize
  *idList: idList(idListSize)

createParser(volumeIdData, endian = l):
  u32 {valid: _ in {0x00..0x06}}: driveType
  u32: driveSerialNumber
  u32: volumeLabelOffset
  u32 {cond: volumeLabelOffset == 0x14}:
    volumeLabelOffsetUnicode
  u8: data{s.atEnd}

# 2.3.1 VolumeID
createParser(volumeId, endian = l):
  u32 {valid: _ > 0x10}: volumeIdSize
  *volumeIdData: data(volumeIdSize - 4)

# 2.3.2 CommonNetworkRelativeLink
createParser(commonNetworkRelativeLink, endian = l):
  u32 {valid: _ >= 0x14}: commonNetworkRelativeLinkSize
  r1: validDevice
  r1: validNetType
  r30: _ = 0
  u32 {valid: _ < commonNetworkRelativeLinkSize}: netNameOffset
  u32 {
    valid: _ < commonNetworkRelativeLinkSize and (validDevice != 0 or _ == 0)
  }: deviceNameOffset
  u32 {
    valid: (validNetType != 0 or _ == 0) and _ in
           constructSet(0x290000, 0x430000, 0x10000)
  }: networkProviderType
  u32 {cond: netNameOffset > 0x14, valid: _ < commonNetworkRelativeLinkSize}:
    netNameOffsetUnicode
  u32 {
    cond: deviceNameOffset > 0x14,
    valid: _ < commonNetworkRelativeLinkSize
  }: deviceNameOffsetUnicode
  s: netName
  s: deviceName
  u16 {cond: netNameOffset > 14}: netNameUnicode
  u16 {cond: deviceNameOffset > 14}: deviceNameUnicode

# 2.3 LinkInfo
createParser(linkInfoHeader, endian = l, size: uint32, headerSize: uint32):
  r1: volumeIdAndLocalBasePath
  r1: commonNetworkRelativeLinkAndPathSuffix
  r30: _ = 0
  u32 {valid: (volumeIdAndLocalBasePath != 0 or _ == 0) and _ < size}:
    volumeIdOffset
  u32 {valid: (volumeIdAndLocalBasePath != 0 or _ == 0) and _ < size}:
    localBasePathOffset
  u32 {valid: commonNetworkRelativeLinkAndPathSuffix != 0 or _ == 0}:
    commonNetworkRelativeLinkOffset
  u32: commonPathSuffixOffset
  u32 {
    cond: headerSize >= 0x24,
    valid: volumeIdAndLocalBasePath != 0 or _ == 0
  }: localBasePathOffsetUnicode
  u32 {cond: headerSize >= 0x24}: commonPathSuffixOffsetUnicode

createParser(linkInfoData, endian = l, size: uint32):
  u32 {valid: _ == 0x1C or _ >= 0x24}: linkInfoHeaderSize
  *linkInfoHeader(size, linkInfoHeaderSize):
    linkInfoHeader(linkInfoHeaderSize - 8)
  *volumeId {
    condPos: (linkInfoHeader.volumeIdAndLocalBasePath.bool,
              linkInfoHeader.volumeIdOffset.int - 4)
  }: volumeId
  s {
    condPos: (linkInfoHeader.volumeIdAndLocalBasePath.bool,
              linkInfoHeader.localBasePathOffset.int - 4)
  }: localBasePath
  *commonNetworkRelativeLink {
    cond: linkInfoHeader.commonNetworkRelativeLinkAndPathSuffix.bool
  }: commonNetworkRelativeLink
  s: commonPathSuffix
  u16 {
    cond: linkInfoHeader.volumeIdAndLocalBasePath.bool and
          linkInfoHeaderSize >= 0x24
  }: localBasePathUnicode{_ == 0}
  u16 {cond: linkInfoHeaderSize >= 0x24}: commonPathSuffixUnicode{_ == 0}

createParser(linkInfo, endian = l):
  u32: linkInfoSize
  *linkInfoData(linkInfoSize): linkInfoData(linkInfoSize - 4)

# 2.4 StringData
createParser(stringData, endian = l):
  u16: countCharacters
  u16: str[countCharacters]

createParser(shellLink):
  *shellLinkHeader: shellLinkHeader
  *linkTargetIdList {cond: shellLinkHeader.linkFlags.hasLinkTargetIdList.bool}:
    linkTargetIdList
  *linkInfo {cond: shellLinkHeader.linkFlags.hasLinkInfo.bool}: linkInfo
  *stringData {cond: shellLinkHeader.linkFlags.hasName.bool}: nameString
  *stringData {cond: shellLinkHeader.linkFlags.hasRelativePath.bool}:
    relativePath
  *stringData {cond: shellLinkHeader.linkFlags.hasWorkingDir.bool}: workingDir
  *stringData {cond: shellLinkHeader.linkFlags.hasArguments.bool}:
    commandLineArguments
  *stringData {cond: shellLinkHeader.linkFlags.hasIconLocation.bool}:
    iconLocation