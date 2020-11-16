import sequtils, strutils, strformat, terminal

proc tab*(cols: varargs[string]) =
  echo cols.mapIt(&"{it:<20}").join(
    ansiForegroundColorCode(fgYellow) & " | " & ansiResetCode)