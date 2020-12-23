import os, sequtils, strutils, strformat, terminal, times, unicode
import bitstreams
import parsers/windows/shelllink

proc tab(cols: varargs[string]) =
  echo cols.mapIt(&"{it:<20}").join(
    ansiForegroundColorCode(fgYellow) & " | " & ansiResetCode)

proc formatWinTime(ts: int64): string =
  fromWinTime(ts).format("dd/MM/yyyy HH:mm:ss:fffffffff") & " (UTC)"

let
  tool = paramStr(1)
  path = paramStr(2)

proc echoData(a: tuple, nesting = 0) =
  for k, v in a.fieldPairs:
    stdout.write " ".repeat(nesting) & k & ": "
    when v is tuple:
      stdout.write "\n"
      echoData(v, nesting + 2)
    elif v is seq:
      stdout.write "\n"
      for e in v:
        when e is tuple:
          echoData(e, nesting + 2)
        else:
          stdout.write " ".repeat(nesting + 2) & $e
          stdout.write "\n"
    else:
      stdout.write v
      stdout.write "\n"

case tool
of "wlf":
  var fs = newFileBitStream(path, fmRead)
  defer: fs.close()
  if not fs.isNil:
    let x = ShellLink.get(fs)
    tab("Linked Path", x.linkInfo.linkInfoData.localBasePath &
                       x.linkInfo.linkInfoData.commonPathSuffix)