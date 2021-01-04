import os, streams, json, strutils, sequtils
import json_serialization, bitstreams
from binarylang import typeGetter
import parsers/windows/[shelllink, prefetch]

let
  op = paramStr(1)
  parser = paramStr(2)
  subject = paramStr(3)
  io = paramStr(4)

if "decode".startsWith(op):
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
  of "winprefetch":
    let
      mam = Mam.get(bs)
      uncompressed = newStringBitStream(mam.data.mapIt(it.char).join)
      x = Prefetch.get(uncompressed)
    s.write(x.toJson(pretty = true))
elif "encode".startsWith(op):
  var
    bs = newFileBitStream(subject, fmReadWrite)
    s = newFileStream(io, fmRead)
  defer:
    close(bs)
    close(s)
  let json = parseJson(s.readAll)
  case parser
  of "winshelllink":
    let x = json.to(typeGetter(ShellLink))
    ShellLink.put(bs, x)
  of "winprefetch":
    let x = json.to(typeGetter(Prefetch))
    Prefetch.put(bs, x)