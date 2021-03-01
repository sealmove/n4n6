# https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

import binarylang, binarylang/plugins, bitstreams

createParser(DosHeader, endian = l):
  s: signature = "MZ"
  u16: lastSize
  u16: nBlocks
  u16: nReloc
  u16: hdrSize
  u16: minAlloc
  u16: maxAlloc
  u16: ss
  u16: sp
  u16: checksum
  u16: ip
  u16: cs
  u16: relocPos
  u16: noOverlay
  u64: reserved1
  u16: oemId
  u16: oemInfo
  u8: reserved2[20]
  u32: peOfs

# createParser(CoffSymbol, endian = l):

# COFF File Header (Object and Image)
createParser(CoffHeader, endian = l):
  u16: machine
  u16: numberOfSections
  u32: timeDateStamp
  u32: pointerToSymbolTable
  u32: numberOfSymbols
  u16: sizeOfOptionalHeader
  u16: characteristics
#  u32 {pos: int(pointerToSymbolTable + numberOfSymbols * 18)}: symbolNameTableSize
#  *CoffSymbol {pos: int(pointerToSymbolTable)}: symbolTable[numberOfSymbols]

createParser(OptionalHeaderStd, endian = l):
  u16 {valid: e in {0x10b, 0x20b, 0x107}}: magic
  u8: majorLinkVersion
  u8: minorLinkVersion
  u32: sizeOfCode
  u32: sizeOfInitializedData
  u32: sizeOfUninitializedData
  u32: addressOfEntryPoint
  u32: baseOfCode
  u32 {cond: magic == 0x10b}: baseOfData

createParser(OptionalHeaderWindowsSpecificPe32, endian = l):
  u32: imageBase
  u32: sectionAlignment
  u32: fileAlignment
  u16: majorOSVersion
  u16: minorOSVersion
  u16: majorImageVersion
  u16: minorImageVersion
  u16: majorSubsystemVersion
  u16: minorSubsystemVersion
  u32: win32VersionValue
  u32: sizeOfImage
  u32: sizeOfHeaders
  u32: checkSum
  u16: subsystem
  u16: dllCharacteristics
  u32: sizeOfStackReserve
  u32: sizeOfStackCommit
  u32: sizeOfHeapReverse
  u32: sizeOfHeapCommit
  u32: loaderFlags
  u32: numberOfRvaAndSizes

createParser(OptionalHeaderWindowsSpecificPe32Plus, endian = l):
  u64: imageBase
  u32: sectionAlignment
  u32: fileAlignment
  u16: majorOSVersion
  u16: minorOSVersion
  u16: majorImageVersion
  u16: minorImageVersion
  u16: majorSubsystemVersion
  u16: minorSubsystemVersion
  u32: win32VersionValue
  u32: sizeOfImage
  u32: sizeOfHeaders
  u32: checkSum
  u16: subsystem
  u16: dllCharacteristics
  u64: sizeOfStackReserve
  u64: sizeOfStackCommit
  u64: sizeOfHeapReverse
  u64: sizeOfHeapCommit
  u32: loaderFlags
  u32: numberOfRvaAndSizes

type PeFormat = enum
  pfNa = 0
  pfPe32 = (0x10b, "PE32")
  pfPe32Plus = (0x20b, "PE32+")

type OptionalHeaderWindowsSpecificTy* = ref object
  case code*: PeFormat
  of pfPe32: optionalHeaderWindowsSpecificPe32*: typeGetter(OptionalHeaderWindowsSpecificPe32)
  of pfPe32Plus: optionalHeaderWindowsSpecificPe32Plus*: typeGetter(OptionalHeaderWindowsSpecificPe32Plus)
  else: discard
proc OptionalHeaderWindowsSpecificGet(s: BitStream, code: PeFormat): OptionalHeaderWindowsSpecificTy =
  result = OptionalHeaderWindowsSpecificTy(code: code)
  case code
  of pfPe32: result.optionalHeaderWindowsSpecificPe32 = OptionalHeaderWindowsSpecificPe32.get(s)
  of pfPe32Plus: result.optionalHeaderWindowsSpecificPe32Plus = OptionalHeaderWindowsSpecificPe32Plus.get(s)
  else: discard
proc OptionalHeaderWindowsSpecificPut(s: BitStream, input: OptionalHeaderWindowsSpecificTy, code: PeFormat) =
  case input.code
  of pfPe32: OptionalHeaderWindowsSpecificPe32.put(s, input.optionalHeaderWindowsSpecificPe32)
  of pfPe32Plus: OptionalHeaderWindowsSpecificPe32Plus.put(s, input.optionalHeaderWindowsSpecificPe32Plus)
  else: discard
let OptionalHeaderWindowsSpecific = (get: OptionalHeaderWindowsSpecificGet, put: OptionalHeaderWindowsSpecificPut)

createParser(DataDirectory, endian = l):
  u32: virtualAddress
  u32: size

createParser(DataDirectories, endian = l):
  *DataDirectory: exportTable
  *DataDirectory: importTable
  *DataDirectory: resourceTable
  *DataDirectory: exceptionTable
  *DataDirectory: certificateTable
  *DataDirectory: baseRelocationTable
  *DataDirectory: debug
  *DataDirectory: architecture
  *DataDirectory: globalPtr
  *DataDirectory: tlsTable
  *DataDirectory: loadConfigTable
  *DataDirectory: boundImport
  *DataDirectory: iat
  *DataDirectory: delayImportDescriptor
  *DataDirectory: clrRuntimeHeader
  *DataDirectory {valid: e.virtualAddress == 0 and e.size == 0}: reserved

createParser(OptionalHeader, endian = l):
  *OptionalHeaderStd: standardFields
  *OptionalHeaderWindowsSpecific(PeFormat(standardFields.magic)): windowsSpecificFields
  *DataDirectories: dataDirectories

createParser(Section, endian = l):
  u64: name
  u32: virtualSize
  u32: virtualAddress
  u32: sizeOfRawData
  u32: pointerToRawData
  u32: pointerToRelocations
  u32: pointerToLineNumbers
  u16: numberOfRelocations
  u16: numberOfLineNumbers
  u32: characteristics
  u8 {pos: int(pointerToRawData)}: rawData[sizeOfRawData]

createParser(PeHeader, endian = l):
  s: signature = "PE\x00\x00"
  *CoffHeader: coffHeader
  *OptionalHeader {cond: coffHeader.sizeOfOptionalHeader > 0}: optionalHeader(coffHeader.sizeOfOptionalHeader)
  *Section: sections[coffHeader.numberOfSections]

createParser(Pe, endian = l):
  *DosHeader: dosHeader
  *PeHeader {pos: int(dosHeader.peOfs)}: peHeader

export Pe