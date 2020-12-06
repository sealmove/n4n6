import streams, options
import ../../binaryparse/binaryparse
import utils

createParser(LinkFlags, littleEndian):
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

createParser(FileHeader, littleEndian):
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

createConditionalParser(LinkTargetIdList, littleEndian):
  u16: lenIdList
  u8: _[lenIdList]

createParser(LinkInfoFlags, littleEndian):
  6: reserved1
  1: hasCommonNetRelLink
  1: hasVolumeIdAndLocalBasePath
  24: reserved2

createParser(Header, littleEndian):
  *LinkInfoFlags: flags
  u32: volumeIdOfs
  u32: localBasePathOfs
  u32: commonNetRelLinkOfs
  u32: commonPathSuffixOfs
  *UInt32IfNotEof: localBasePathOfsUnicode
  *UInt32IfNotEof: commonPathSuffixOfsUnicode

createParser(LinkInfoBody, littleEndian):
  u32: headerSize
  *Header: header

createConditionalParser(LinkInfo, littleEndian):
  u32: size
  *LinkInfoBody: linkInfoBody

createParser(WindowsLinkFile):
  *FileHeader: header
  *LinkTargetIdList(header.flags.hasLinkTargetIdList.bool): targetIdList
  *LinkInfo(header.flags.hasLinkInfo.bool): info

export WindowsLinkFile