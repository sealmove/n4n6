import streams, options
import ../../binaryparse/binaryparse

createParser(LinkFlags, endian = little):
  1: isUnicode
  1: hasIconLocation
  1: hasArguments
  1: hasWorkingDir
  1: hasRelativePath
  1: hasName
  1: hasLinkInfo
  1: hasLinkTargetIdList
  16: _
  5: reserved
  1: keepLocalIdListForUncTarget
  2: _

createParser(FileHeader, endian = little):
  s: lenHeader = "\x4c\x00\x00\x00"
  s: linkClsid = "\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
  *LinkFlags: flags
  u32: fileAttrs
  64: timeCreation
  64: timeAccess
  64: timeWrite
  u32: targetFileSize
  32: iconIndex
  u32: showCommand
  u16: hotkey
  s: reserved = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

createParser(LinkTargetIdList, endian = little):
  u16: lenIdList
  u8: _[lenIdList]

createParser(LinkInfoFlags, endian = little):
  6: reserved1
  1: hasCommonNetRelLink
  1: hasVolumeIdAndLocalBasePath
  24: reserved2

createParser(VolumeIdBody, endian = little):
  u32: driveType
  u32: driveSerialNumber
  u32: volumeLabelOfs
  u32 {cond: volumeLabelOfs == 0x14}: volumeLabelOfsUnicode

createParser(VolumeId, endian = little):
  u32: len
  *VolumeIdBody {size: len - 4}: body

createParser(Header, endian = little):
  *LinkInfoFlags: flags
  u32: volumeIdOfs
  u32: localBasePathOfs
  u32: commonNetRelLinkOfs
  u32: commonPathSuffixOfs
  u32 {cond: not stream.atEnd}: localBasePathOfsUnicode
  u32 {cond: not stream.atEnd}: commonPathSuffixOfsUnicode

createParser(LinkInfoBody, endian = little):
  u32: headerSize
  *Header {size: headerSize - 8}: header
  *VolumeId {cond: header.flags.hasVolumeIdAndLocalBasePath,
             pos: header.volumeIdOfs}: volumeId
  u8 {cond: header.flags.hasVolumeIdAndLocalBasePath,
      pos: header.localBasePathOfs - 4,
      terminator: '\0'}: localBasePath[]

createParser(LinkInfo, little):
  u32: size
  *LinkInfoBody {size: size - 4}: linkInfoBody

createParser(StringData, endian = little):
  u16: chars
  u8: str[chars * 2]

createParser(WindowsLinkFile):
  *FileHeader: header
  *LinkTargetIdList {cond: header.flags.hasLinkTargetIdList}: targetIdList
  *LinkInfo {cond: header.flags.hasLinkInfo}: info
  *StringData {cond: header.flags.hasRelativePath}: name

export WindowsLinkFile