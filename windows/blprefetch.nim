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
struct(*mam, endian = l):
  s: _ = "MAM\x04"
  u32: *size
  *lz77Huffman(size): *data

# 4.1 File header
struct(*header, endian = l):
  u32: *version
  s: _ = "SCCA"
  u32: *unknown1
  u32: *fileSize
  u16: *exeFilename[29]
  u16: _ = 0
  u32: *hash
  u32: *unknown2

# 4.2 File information
struct(*fileInfo17, endian = l):
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

struct(*fileInfo23, endian = l):
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

struct(*fileInfo26, endian = l):
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

struct(*fileInfo30, endian = l):
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

union(*fileInfo, *PrefetchVersion):
  (pv17): *fileInfo17: *fi17
  (pv23): *fileInfo23: *fi23
  (pv26): *fileInfo26: *fi26
  (pv30): *fileInfo30: *fi30
  _: nil

proc fileMetricsOfs*(o: FileInfo): uint32 =
  case o.disc
  of pv17: result = o.fi17.fileMetricsOfs
  of pv23: result = o.fi23.fileMetricsOfs
  of pv26: result = o.fi26.fileMetricsOfs
  of pv30: result = o.fi30.fileMetricsOfs
  else: discard
proc fileMetricsEntries*(o: FileInfo): uint32 =
  case o.disc
  of pv17: result = o.fi17.fileMetricsEntries
  of pv23: result = o.fi23.fileMetricsEntries
  of pv26: result = o.fi26.fileMetricsEntries
  of pv30: result = o.fi30.fileMetricsEntries
  else: discard
proc traceChainsOfs*(o: FileInfo): uint32 =
  case o.disc
  of pv17: result = o.fi17.traceChainsOfs
  of pv23: result = o.fi23.traceChainsOfs
  of pv26: result = o.fi26.traceChainsOfs
  of pv30: result = o.fi30.traceChainsOfs
  else: discard
proc traceChainsEntries*(o: FileInfo): uint32 =
  case o.disc
  of pv17: result = o.fi17.traceChainsEntries
  of pv23: result = o.fi23.traceChainsEntries
  of pv26: result = o.fi26.traceChainsEntries
  of pv30: result = o.fi30.traceChainsEntries
  else: discard
proc filenameStringsOfs*(o: FileInfo): uint32 =
  case o.disc
  of pv17: result = o.fi17.filenameStringsOfs
  of pv23: result = o.fi23.filenameStringsOfs
  of pv26: result = o.fi26.filenameStringsOfs
  of pv30: result = o.fi30.filenameStringsOfs
  else: discard
proc filenameStringsSize*(o: FileInfo): uint32 =
  case o.disc
  of pv17: result = o.fi17.filenameStringsSize
  of pv23: result = o.fi23.filenameStringsSize
  of pv26: result = o.fi26.filenameStringsSize
  of pv30: result = o.fi30.filenameStringsSize
  else: discard

# 4.3 File metrics array
struct(*fileMetric17, endian = l):
  u32: *unknown1
  u32: *unknown2
  u32: *filenameStringsOfs
  u32: *filenameStringsChars
  u32: *unknown3

struct(*fileMetric23, endian = l):
  u32: *unknown1
  u32: *unknown2
  u32: *unknown3
  u32: *filenameStringsOfs
  u32: *filenameStringsChars
  u32: *unknown4
  u64: *fileRef

union(*fileMetric, *PrefetchVersion):
  (pv17): *fileMetric17: *fm17
  _: *fileMetric23: *fm23

# 4.4 Trace chains array
struct(*traceChain17, endian = l):
  u32: *nextIndex
  u32: *blocksLoaded
  u8: *unknown1
  u8: *unknown2
  u16: *unknown3

struct(*traceChain30, endian = l):
  u32: *blocksLoaded
  u8: *unknown1
  u8: *unknown2
  u16: *unknown3

union(*traceChain, *PrefetchVersion):
  (pv17): *traceChain17: *tc17
  _: *traceChain30: *tc30

# 4.5 Filename strings
struct(*filenameString, endian = l):
  u16: *str{_ == 0 or s.atEnd}

struct(*filenameStrings):
  *filenameString: *strs{s.atEnd}

# 4 Uncompressed Prefetch file
struct(prefetch, endian = l):
  *header: *prefetchHeader
  +fileInfo(prefetchHeader.version.PrefetchVersion): *info
  +fileMetric(prefetchHeader.version.PrefetchVersion) {
    pos(info.fileMetricsOfs.int)
  }: *fileMetrics[info.fileMetricsEntries]
  +traceChain(prefetchHeader.version.PrefetchVersion) {
    pos(info.traceChainsOfs.int)
  }: *traceChains[info.traceChainsEntries]
  *filenameStrings {pos(info.filenameStringsOfs.int)}:
    *filenames(info.filenameStringsSize.int)
