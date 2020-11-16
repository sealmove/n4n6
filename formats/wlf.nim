import streams, times
import binaryparse
import ../utils

proc formatWinTime(ts: int64): string =
  fromWinTime(ts).format("dd/MM/yyyy HH:mm:ss:fffffffff") & " (UTC)"

createParser(linkFlags):
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

createParser(fileHeader):
  s: lenHeader = "\x4c\x00\x00\x00"
  s: linkClsid = "\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
  *linkFlags: flags
  u32: fileAttrs
  64: timeCreation
  64: timeAccess
  64: timeWrite
  u32: targetFileSize
  32: iconIndex
  u32: showCommand
  u16: hotkey
  s: reserved = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

createParser(windowsLinkFile):
  *fileHeader: header

proc print*(path: string) =
  var fs = newFileStream(path, fmRead)
  defer: fs.close()
  if not fs.isNil:
    let x = windowsLinkFile.get(fs)
    tab("Time Creation", x.header.timeCreation.formatWinTime)
    tab("Time Access", x.header.timeAccess.formatWinTime)
    tab("Time Write", x.header.timeWrite.formatWinTime)