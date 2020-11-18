import os, streams, options, sequtils, strutils, strformat, terminal, times
import parsers/windows_link_file

proc tab(cols: varargs[string]) =
  echo cols.mapIt(&"{it:<20}").join(
    ansiForegroundColorCode(fgYellow) & " | " & ansiResetCode)

proc formatWinTime(ts: int64): string =
  fromWinTime(ts).format("dd/MM/yyyy HH:mm:ss:fffffffff") & " (UTC)"

let
  tool = paramStr(1)
  path = paramStr(2)

case tool
of "wlf":
  var fs = newFileStream(path, fmRead)
  defer: fs.close()
  if not fs.isNil:
    let x = WindowsLinkFile.get(fs)
    tab("Time Creation", x.header.timeCreation.formatWinTime)
    tab("Time Access", x.header.timeAccess.formatWinTime)
    tab("Time Write", x.header.timeWrite.formatWinTime)
    if isSome(x.targetIdList):
      tab("len_id_list", $x.targetIdList.get.len_id_list)