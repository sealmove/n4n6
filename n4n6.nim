import os, streams, sequtils, strutils, strformat, terminal, times
import bitstreams
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
  var fs = newFileBitStream(path, fmRead)
  defer: fs.close()
  if not fs.isNil:
    discard
    #let x = ShellLinkHeader.get(fs)