# https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc

import sequtils, strutils
import binarylang, bitstreams, lz77

type PrefetchVersion* = enum
  pv1 = (17, "Windows XP/2003")
  pv2 = (23, "Windows Vista/7")
  pv3 = (26, "Windows 8.1")
  pv4 = (30, "Windows 10")

proc lz77HuffmanGet(s: BitStream, size: uint32): seq[byte] =
  while not s.atEnd:
    result.add s.readU8
  decompressMam(result, size.int)
proc lz77HuffmanPut(s: BitStream, input: seq[byte], size: uint32) =
  writeStr(s, input.mapIt(it.char).join)
let Lz77Huffman = (get: lz77HuffmanGet, put: lz77HuffmanPut) 

# 3 Compressed Prefetch file - MAM file format
createParser(Mam, endian = l):
  s: _ = "MAM\x04"
  u32: size
  *Lz77Huffman(size): data

# 4.1 File header
createParser(Header, endian = l):
  u32: version
  s: _ = "SCCA"
  u32: unknown1
  u32: fileSize
  u16: exeFilename[29]
  u8: _ = 0
  u32: hash
  u32: unknown2

# 4 Uncompressed Prefetch file
createParser(Prefetch, endian = l):
  *Header: header

export Mam, Prefetch