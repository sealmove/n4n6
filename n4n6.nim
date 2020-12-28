import os, streams, json, strutils
import json_serialization, bitstreams
from binarylang import typeGetter
import windows/shelllink

let
  op = paramStr(1)
  format = paramStr(2)
  parser = paramStr(3)
  subject = paramStr(4)
  io = paramStr(5)

if "encode".startsWith(op):
  var
    bs = newFileBitStream(subject, fmReadWrite)
    s = newFileStream(io, fmRead)
  defer:
    close(bs)
    close(s)
  case parser
  of "winshelllink":
    let
      json = parseJson(s.readAll)
      x = json.to(typeGetter(ShellLink))
    ShellLink.put(bs, x)
elif "decode".startsWith(op):
  var
    bs = newFileBitStream(subject, fmRead)
    s = newFileStream(io, fmWrite)
  defer:
    close(bs)
    close(s)
  case parser
  of "winshelllink":
    let x = ShellLink.get(bs)
    s.write(x.toJson(pretty = true))