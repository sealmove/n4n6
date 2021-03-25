# https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc

import sequtils, strutils
import binarylang, binarylang/plugins, lz77

type PrefetchVersion* = enum
  pvNA = (0, "NA")
  pv17 = (17, "Windows XP/2003")
  pv23 = (23, "Windows Vista/7")
  pv26 = (26, "Windows 8.1")
  pv30 = (30, "Windows 10")

type Lz77Huffman* = seq[byte]
proc lz77HuffmanGet(s: BitStream, size: uint32): seq[byte] =
  while not s.atEnd:
    result.add s.readU8
  decompressMam(result, size.int)
proc lz77HuffmanPut(s: BitStream, input: seq[byte], size: uint32) =
  writeStr(s, input.mapIt(it.char).join)
let lz77Huffman* = (get: lz77HuffmanGet, put: lz77HuffmanPut) 

# 3 Compressed Prefetch file - MAM file format
createParser(*mam, endian = l):
  s: _ = "MAM\x04"
  u32: *size
  *lz77Huffman(size): *data

# 4.1 File header
createParser(*header, endian = l):
  u32: *version
  s: _ = "SCCA"
  u32: *unknown1
  u32: *fileSize
  u16: *exeFilename[29]
  u16: _ = 0
  u32: *hash
  u32: *unknown2

# 4.2 File information
createParser(*fileInfo17, endian = l):
  u32: *fileMetricsOfs = 152
  u32: *fileMetricsEntries
  u32: *traceChainsOfs
  u32: *traceChainsEntries
  u32: *filenameStringsOfs
  u32: *filenameStringsSize
  u32: *volumesOfs
  u32: *volumesEntries
  u32: *volumesSize
  u64: *lastRunTime
  u8: *unknown1[16]
  u32: *runCount
  u32: *unknown2

createParser(*fileInfo23, endian = l):
  u32: *fileMetricsOfs = 240
  u32: *fileMetricsEntries
  u32: *traceChainsOfs
  u32: *traceChainsEntries
  u32: *filenameStringsOfs
  u32: *filenameStringsSize
  u32: *volumesOfs
  u32: *volumesEntries
  u32: *volumesSize
  u64: *unknown1
  u64: *lastRunTime
  u8: *unknown2[16]
  u32: *runCount
  u32: *unknown3
  u8: *unknown4[80]

createParser(*fileInfo26, endian = l):
  u32: *fileMetricsOfs = 304
  u32: *fileMetricsEntries
  u32: *traceChainsOfs
  u32: *traceChainsEntries
  u32: *filenameStringsOfs
  u32: *filenameStringsSize
  u32: *volumesOfs
  u32: *volumesEntries
  u32: *volumesSize
  u64: *unknown1
  u64: *lastRunTimes[8]
  u8: *unknown2[16]
  u32: *runCount
  u32: *unknown3
  u32: *unknown4
  u8: *unknown5[88]

createParser(*fileInfo30, endian = l):
  u32: *fileMetricsOfs = 296
  u32: *fileMetricsEntries
  u32: *traceChainsOfs
  u32: *traceChainsEntries
  u32: *filenameStringsOfs
  u32: *filenameStringsSize
  u32: *volumesOfs
  u32: *volumesEntries
  u32: *volumesSize
  u64: *unknown1
  u64: *lastRunTimes[8]
  u64: *unknown2
  u32: *runCount
  u32: *unknown3
  u32: *unknown4
  u8: *unknown5[88]

createVariantParser(*fileInfo, *version: PrefetchVersion):
  (pv17): *fileInfo17: *fileInfo17
  (pv23): *fileInfo23: *fileInfo23
  (pv26): *fileInfo26: *fileInfo26
  (pv30): *fileInfo30: *fileInfo30
  _: nil

proc fileMetricsOfs*(o: FileInfo): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.fileMetricsOfs
  of pv23: result = o.fileInfo23.fileMetricsOfs
  of pv26: result = o.fileInfo26.fileMetricsOfs
  of pv30: result = o.fileInfo30.fileMetricsOfs
  else: discard
proc fileMetricsEntries*(o: FileInfo): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.fileMetricsEntries
  of pv23: result = o.fileInfo23.fileMetricsEntries
  of pv26: result = o.fileInfo26.fileMetricsEntries
  of pv30: result = o.fileInfo30.fileMetricsEntries
  else: discard
proc traceChainsOfs*(o: FileInfo): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.traceChainsOfs
  of pv23: result = o.fileInfo23.traceChainsOfs
  of pv26: result = o.fileInfo26.traceChainsOfs
  of pv30: result = o.fileInfo30.traceChainsOfs
  else: discard
proc traceChainsEntries*(o: FileInfo): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.traceChainsEntries
  of pv23: result = o.fileInfo23.traceChainsEntries
  of pv26: result = o.fileInfo26.traceChainsEntries
  of pv30: result = o.fileInfo30.traceChainsEntries
  else: discard
proc filenameStringsOfs*(o: FileInfo): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.filenameStringsOfs
  of pv23: result = o.fileInfo23.filenameStringsOfs
  of pv26: result = o.fileInfo26.filenameStringsOfs
  of pv30: result = o.fileInfo30.filenameStringsOfs
  else: discard
proc filenameStringsSize*(o: FileInfo): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.filenameStringsSize
  of pv23: result = o.fileInfo23.filenameStringsSize
  of pv26: result = o.fileInfo26.filenameStringsSize
  of pv30: result = o.fileInfo30.filenameStringsSize
  else: discard

# 4.3 File metrics array
createParser(*fileMetric17, endian = l):
  u32: *unknown1
  u32: *unknown2
  u32: *filenameStringsOfs
  u32: *filenameStringsChars
  u32: *unknown3

createParser(*fileMetric23, endian = l):
  u32: *unknown1
  u32: *unknown2
  u32: *unknown3
  u32: *filenameStringsOfs
  u32: *filenameStringsChars
  u32: *unknown4
  u64: *fileRef

createVariantParser(*fileMetric, *version: PrefetchVersion):
  (pv17): *fileMetric17: *fileMetric17
  _: *fileMetric23: *fileMetric23

# 4.4 Trace chains array
createParser(*traceChain17, endian = l):
  u32: *nextIndex
  u32: *blocksLoaded
  u8: *unknown1
  u8: *unknown2
  u16: *unknown3

createParser(*traceChain30, endian = l):
  u32: *blocksLoaded
  u8: *unknown1
  u8: *unknown2
  u16: *unknown3

createVariantParser(*traceChain, *version: PrefetchVersion):
  (pv17): *traceChain17: *traceChain17
  _: *traceChain30: *traceChain30

# 4.5 Filename strings
createParser(*filenameString, endian = l):
  u16: *str{_ == 0 or s.atEnd}

createParser(*filenameStrings):
  *filenameString: *strs{s.atEnd}

# 4 Uncompressed Prefetch file
createParser(prefetch, endian = l):
  *header: *prefetchHeader
  *fileInfo(prefetchHeader.version.PrefetchVersion): *info
  *fileMetric(prefetchHeader.version.PrefetchVersion) {
    pos: info.fileMetricsOfs.int}: *fileMetrics[info.fileMetricsEntries]
  *traceChain(prefetchHeader.version.PrefetchVersion) {
    pos: info.traceChainsOfs.int}: *traceChains[info.traceChainsEntries]
  *filenameStrings {pos: info.filenameStringsOfs.int}:
    *filenames(info.filenameStringsSize.int)