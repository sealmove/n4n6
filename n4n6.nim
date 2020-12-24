import os, sequtils, strutils, strformat, terminal, times, unicode, bitops
import bitstreams
from binarylang import typeGetter
import parsers/windows/[shellitem, shelllink]

proc tab(cols: varargs[string]) =
  echo cols.mapIt(&"{it:<50}").join(
    ansiForegroundColorCode(fgYellow) & " | " & ansiResetCode)

proc formatWinTime(ts: int64): string =
  fromWinTime(ts).format("dd/MM/yyyy HH:mm:ss:fffffffff") & " (UTC)"

proc formatClsId(id: typeGetter(ClsId)): string =
  let
    p1 = id.part1.toHex(8).toLowerAscii
    p2 = id.part2.toHex(4).toLowerAscii
    p3 = id.part3.toHex(4).toLowerAscii
    p4 = id.part4.toHex(4).toLowerAscii
    p5 = id.part5.mapIt(it.toHex(2)).join.toLowerAscii
  "{" & &"{p1}-{p2}-{p3}-{p4}-{p5}" & "}"

#                24                16                 8                 0
# +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
# |Y|Y|Y|Y|Y|Y|Y|M| |M|M|M|D|D|D|D|D| |h|h|h|h|h|m|m|m| |m|m|m|s|s|s|s|s|
# +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
#  \___________/\________/\_________/ \________/\____________/\_________/
#     year        month       day      hour       minute        second
# The year is stored as an offset from 1980
# Seconds are stored in two-second increments
proc formatFatTime(ts: typeGetter(FatTime)): string =
  let
    y = (ts.low shr 9) + 1980
    M = ts.low.masked(5 .. 8) shr 5
    d = ts.low.masked(0 .. 4)
    H = ts.high shr 11
    m = ts.high.masked(5 .. 10) shr 5
    s = ts.high.masked(0 .. 5)
  result = &"{d:02}/{M:02}/{y:04} {H:02}:{m:02}:{s:02} (UTC)"

let
  tool = paramStr(1)
  path = paramStr(2)

case tool
of "wlf":
  var fs = newFileBitStream(path, fmRead)
  defer: fs.close()
  if not fs.isNil:
    let x = ShellLink.get(fs)
    if x.linkInfo.linkInfoData.linkInfoHeader.volumeIdAndLocalBasePath.bool:
      tab("Linked Path", x.linkInfo.linkInfoData.localBasePath &
                        x.linkInfo.linkInfoData.commonPathSuffix)
    if x.shellLinkHeader.linkFlags.hasArguments.bool:
      tab("Arguments", $x.commandLineArguments.str.mapIt(it.Rune))
    tab("Created", x.shellLinkHeader.creationTime.formatWinTime)
    tab("Last Accessed", x.shellLinkHeader.accessTime.formatWinTime)
    tab("Last Modified", x.shellLinkHeader.writeTime.formatWinTime)
    for i, item in x.linkTargetIdList.idList.itemIdList:
      case item.data.code
      of 0x10:
        tab(&"Shellbag #{i+1} (root folder): Sort Index", $item.data.rootFolder.sortIndex)
        tab(&"Shellbag #{i+1} (root folder): Shell Folder ID", item.data.rootFolder.shellFolderId.formatClsId)
      of 0x20:
        tab(&"Shellbag #{i+1} (volume): Has Name", $bool(item.data.volume.flags and 0x01))
        tab(&"Shellbag #{i+1} (volume): Is Removable Media", $bool(item.data.volume.flags and 0x08))
      of 0x30:
        tab(&"Shellbag #{i+1} (file entry): File Size", $item.data.fileEntry.fileSize)
        tab(&"Shellbag #{i+1} (file entry): Write Time", item.data.fileEntry.writeTime.formatFatTime)
        let name = if (item.clsTypeId and 0x04) == 0: item.data.fileEntry.primaryName
                   else: $item.data.fileEntry.primaryNameUnicode.mapIt(it.Rune)
        tab(&"Shellbag #{i+1} (file entry): Name", name)
      else: discard