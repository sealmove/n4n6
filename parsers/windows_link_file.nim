import streams, options
import binaryparse
import utils

createParser(LinkFlags):
  1: isUnicode
  1: hasIconLocation
  1: hasArguments
  1: hasWorkingDir
  1: hasRelativePath
  1: hasName
  1: hasLinkInfo
  1: hasLinkTargetIdList
  l16: _
  5: reserved
  1: keepLocalIdListForUncTarget
  2: _

createParser(FileHeader):
  s: lenHeader = "\x4c\x00\x00\x00"
  s: linkClsid = "\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
  *LinkFlags: flags
  lu32: fileAttrs
  l64: timeCreation
  l64: timeAccess
  l64: timeWrite
  lu32: targetFileSize
  l32: iconIndex
  lu32: showCommand
  lu16: hotkey
  s: reserved = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

createParser(linkTargetIdList):
  lu16: lenIdList
  u8: _[lenIdList]

createConditionalParser(linkTargetIdList, LinkTargetIdList)

createParser(LinkInfoFlags):
  6: reserved1
  1: hasCommonNetRelLink
  1: hasVolumeIdAndLocalBasePath
  l24: reserved2

createParser(Header):
  *LinkInfoFlags: flags
  lu32: volumeIdOfs
  lu32: localBasePathOfs
  lu32: commonNetRelLinkOfs
  lu32: commonPathSuffixOfs
  *UInt32IfNotEof: localBasePathOfsUnicode
  *UInt32IfNotEof: commonPathSuffixOfsUnicode

createParser(LinkInfoBody):
  lu32: headerSize
  *Header: header

createParser(linkInfo):
  lu32: size
  *LinkInfoBody: linkInfoBody

createConditionalParser(linkInfo, LinkInfo)

createParser(WindowsLinkFile):
  *FileHeader: header
  *LinkTargetIdList(header.flags.hasLinkTargetIdList.bool): targetIdList
  *LinkInfo(header.flags.hasLinkInfo.bool): info

export WindowsLinkFile