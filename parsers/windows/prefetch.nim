# https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc

import sequtils, strutils
import binarylang, binarylang/plugins, bitstreams, lz77

type PrefetchVersion* = enum
  pvNA = (0, "NA")
  pv17 = (17, "Windows XP/2003")
  pv23 = (23, "Windows Vista/7")
  pv26 = (26, "Windows 8.1")
  pv30 = (30, "Windows 10")

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
  u16: _ = 0
  u32: hash
  u32: unknown2

# 4.2 File information
createParser(FileInfo17, endian = l):
  u32: fileMetricsOfs = 152
  u32: fileMetricsEntries
  u32: traceChainsOfs
  u32: traceChainsEntries
  u32: filenameStringsOfs
  u32: filenameStringsSize
  u32: volumesOfs
  u32: volumesEntries
  u32: volumesSize
  u64: lastRunTime
  u8: unknown1[16]
  u32: runCount
  u32: unknown2

createParser(FileInfo23, endian = l):
  u32: fileMetricsOfs = 240
  u32: fileMetricsEntries
  u32: traceChainsOfs
  u32: traceChainsEntries
  u32: filenameStringsOfs
  u32: filenameStringsSize
  u32: volumesOfs
  u32: volumesEntries
  u32: volumesSize
  u64: unknown1
  u64: lastRunTime
  u8: unknown2[16]
  u32: runCount
  u32: unknown3
  u8: unknown4[80]

createParser(FileInfo26, endian = l):
  u32: fileMetricsOfs = 304
  u32: fileMetricsEntries
  u32: traceChainsOfs
  u32: traceChainsEntries
  u32: filenameStringsOfs
  u32: filenameStringsSize
  u32: volumesOfs
  u32: volumesEntries
  u32: volumesSize
  u64: unknown1
  u64: lastRunTimes[8]
  u8: unknown2[16]
  u32: runCount
  u32: unknown3
  u32: unknown4
  u8: unknown5[88]

createParser(FileInfo30, endian = l):
  u32: fileMetricsOfs = 296
  u32: fileMetricsEntries
  u32: traceChainsOfs
  u32: traceChainsEntries
  u32: filenameStringsOfs
  u32: filenameStringsSize
  u32: volumesOfs
  u32: volumesEntries
  u32: volumesSize
  u64: unknown1
  u64: lastRunTimes[8]
  u64: unknown2
  u32: runCount
  u32: unknown3
  u32: unknown4
  u8: unknown5[88]

type FileInfoTy* = ref object
  case version*: PrefetchVersion
  of pv17: fileInfo17*: typeGetter(FileInfo17)
  of pv23: fileInfo23*: typeGetter(FileInfo23)
  of pv26: fileInfo26*: typeGetter(FileInfo26)
  of pv30: fileInfo30*: typeGetter(FileInfo30)
  else: discard
proc fileInfoGet(s: BitStream, version: uint32): FileInfoTy =
  result = FileInfoTy(version: version.PrefetchVersion)
  case version
  of 17: result.fileInfo17 = FileInfo17.get(s)
  of 23: result.fileInfo23 = FileInfo23.get(s)
  of 26: result.fileInfo26 = FileInfo26.get(s)
  of 30: result.fileInfo30 = FileInfo30.get(s)
  else: discard
proc fileInfoPut(s: BitStream, input: FileInfoTy, version: uint32) =
  case input.version
  of pv17: FileInfo17.put(s, input.fileInfo17)
  of pv23: FileInfo23.put(s, input.fileInfo23)
  of pv26: FileInfo26.put(s, input.fileInfo26)
  of pv30: FileInfo30.put(s, input.fileInfo30)
  else: discard
let FileInfo = (get: fileInfoGet, put: fileInfoPut)
proc fileMetricsOfs*(o: FileInfoTy): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.fileMetricsOfs
  of pv23: result = o.fileInfo23.fileMetricsOfs
  of pv26: result = o.fileInfo26.fileMetricsOfs
  of pv30: result = o.fileInfo30.fileMetricsOfs
  else: discard
proc fileMetricsEntries*(o: FileInfoTy): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.fileMetricsEntries
  of pv23: result = o.fileInfo23.fileMetricsEntries
  of pv26: result = o.fileInfo26.fileMetricsEntries
  of pv30: result = o.fileInfo30.fileMetricsEntries
  else: discard
proc traceChainsOfs*(o: FileInfoTy): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.traceChainsOfs
  of pv23: result = o.fileInfo23.traceChainsOfs
  of pv26: result = o.fileInfo26.traceChainsOfs
  of pv30: result = o.fileInfo30.traceChainsOfs
  else: discard
proc traceChainsEntries*(o: FileInfoTy): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.traceChainsEntries
  of pv23: result = o.fileInfo23.traceChainsEntries
  of pv26: result = o.fileInfo26.traceChainsEntries
  of pv30: result = o.fileInfo30.traceChainsEntries
  else: discard
proc filenameStringsOfs*(o: FileInfoTy): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.filenameStringsOfs
  of pv23: result = o.fileInfo23.filenameStringsOfs
  of pv26: result = o.fileInfo26.filenameStringsOfs
  of pv30: result = o.fileInfo30.filenameStringsOfs
  else: discard
proc filenameStringsSize*(o: FileInfoTy): uint32 =
  case o.version
  of pv17: result = o.fileInfo17.filenameStringsSize
  of pv23: result = o.fileInfo23.filenameStringsSize
  of pv26: result = o.fileInfo26.filenameStringsSize
  of pv30: result = o.fileInfo30.filenameStringsSize
  else: discard

# 4.3 File metrics array
createParser(FileMetric17, endian = l):
  u32: unknown1
  u32: unknown2
  u32: filenameStringsOfs
  u32: filenameStringsChars
  u32: unknown3

createParser(FileMetric23, endian = l):
  u32: unknown1
  u32: unknown2
  u32: unknown3
  u32: filenameStringsOfs
  u32: filenameStringsChars
  u32: unknown4
  u64: fileRef

type FileMetricTy* = ref object
  case version*: PrefetchVersion
  of pv17: fileMetric17*: typeGetter(FileMetric17)
  else: fileMetric23*: typeGetter(FileMetric23)
proc fileMetricGet(s: BitStream, version: uint32): FileMetricTy =
  result = FileMetricTy(version: version.PrefetchVersion)
  case version
  of 17: result.fileMetric17 = FileMetric17.get(s)
  else: result.fileMetric23 = FileMetric23.get(s)
proc fileMetricPut(s: BitStream, input: FileMetricTy, version: uint32) =
  case input.version
  of pv17: FileMetric17.put(s, input.fileMetric17)
  else: FileMetric23.put(s, input.fileMetric23)
let FileMetric = (get: fileMetricGet, put: fileMetricPut)

# 4.4 Trace chains array
createParser(TraceChain17, endian = l):
  u32: nextIndex
  u32: blocksLoaded
  u8: unknown1
  u8: unknown2
  u16: unknown3

createParser(TraceChain30, endian = l):
  u32: blocksLoaded
  u8: unknown1
  u8: unknown2
  u16: unknown3

type TraceChainTy* = ref object
  case version*: PrefetchVersion
  of pv17: traceChain17*: typeGetter(TraceChain17)
  else: traceChain30*: typeGetter(TraceChain30)
proc traceChainGet(s: BitStream, version: uint32): TraceChainTy =
  result = TraceChainTy(version: version.PrefetchVersion)
  case version
  of 17: result.traceChain17 = TraceChain17.get(s)
  else: result.traceChain30 = TraceChain30.get(s)
proc traceChainPut(s: BitStream, input: TraceChainTy, version: uint32) =
  case input.version
  of pv17: TraceChain17.put(s, input.traceChain17)
  else: TraceChain30.put(s, input.traceChain30)
let TraceChain = (get: traceChainGet, put: traceChainPut)

# 4.5 Filename strings
createParser(FilenameString, endian = l):
  u16: str{e == 0 or s.atEnd}

createParser(FilenameStrings):
  *FilenameString: strs{s.atEnd}

# 4 Uncompressed Prefetch file
createParser(Prefetch, endian = l):
  *Header: header
  *FileInfo(header.version): fileInfo
  *FileMetric(header.version) {pos: fileInfo.fileMetricsOfs.int}:
    fileMetrics[fileInfo.fileMetricsEntries]
  *TraceChain(header.version) {pos: fileInfo.traceChainsOfs.int}:
    traceChains[fileInfo.traceChainsEntries]
  *FilenameStrings {pos: fileInfo.filenameStringsOfs.int}:
    filenameStrings(fileInfo.filenameStringsSize.int)

export Mam, Prefetch