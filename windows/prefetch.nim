import streams, sequtils, strutils
import binarylang, bitstreams, lz77

proc lz77HuffmanGet(s: BitStream, size: uint32): seq[byte] =
  while not s.atEnd:
    result.add s.readU8
  decompressMam(result, size.int)

proc lz77HuffmanPut(s: BitStream, input: seq[byte], size: uint32) =
  writeStr(s, input.mapIt(it.char).join)

let Lz77Huffman = (get: lz77HuffmanGet, put: lz77HuffmanPut) 

createParser(Prefetch, endian = l):
  s: _ = "MAM\x04"
  u32: size
  *Lz77Huffman(size): data

export Prefetch