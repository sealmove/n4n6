import binarylang, bitstreams, strutils

createParser(IhdrChuck):
  u32: width
  u32: height
  u8: bitDepth
  u8: colorKind
  u8: compressionMethod
  u8: filterMethod
  u8: interlaceMethod

createParser(Rgb):
  u8: r
  u8: g
  u8: b

createParser(Point):
  u32: x
  u32: y

createParser(PlteChuck):
  *Rgb: pixels{s.atEnd}

type
  ChunkKind* = enum
    ckPlte = "PLTE"
    ckIdat = "IDAT"
    ckChrm = "cHRM"
    ckGama = "gAMA"
    ckSrgb = "sRGB"
    ckBkgd = "bKGD"
    ckPhys = "pHYs"
    ckTime = "tIME"
    ckInternationalText = "iTXt"
    ckText = "tEXt"
    ckCompressedText = "zTXt"
    ckIend = "IEND"
  ColorKind* = enum
    ckGreyscale = 0
    ckTruecolor = 2
    ckIndexed = 3
    ckGreyscaleAlpha = 4
    ckTruecolorAlpha = 6
  PhysUnitKind* = enum
    pukUnknown
    pukMeter
  CompressionMethodKind* = enum
    cmkZlib

createVariantParser(Bkgd, BkgdTy, color: ColorKind):
  (ckGreyscale, ckGreyscaleAlpha):
    u16: *greyscale
  (ckTruecolor, ckTruecolorAlpha):
    u16: *red
    u16: *green
    u16: *blue
  (ckIndexed):
    u8: *paletteIndex

createVariantParser(ChunkData, ChunkTy, typ: ChunkKind, color: ColorKind):
  (ckPlte):
    *Rgb: *entries{s.atEnd}
  (ckIdat):
    u8: *idat{s.atEnd}
  (ckChrm):
    *Point: *whitePoint
    *Point: *redPoint
    *Point: *greenPoint
    *Point: *bluePoint
  (ckGama):
    u32: *gammaInt
  (ckSrgb):
    u8: *renderIntent
  (ckBkgd):
    *Bkgd(color): *bkgd
  (ckPhys):
    u32: *pixelsPerUnitX
    u32: *pixelsPerUnitY
    u8: *unit
  (ckTime):
    u16: *year
    u8: *month
    u8: *day
    u8: *minute
    u8: *second
  (ckInternationalText):
    s: *itKeyword
    u8: *compressionFlag
    u8: *itCompressionMethod
    s: *languageTag
    s: *translatedKeyword
    s: *internationalText
  (ckText):
    s: *textKeyword
    s: *text
  (ckCompressedText):
    s: *compressedTextKeyword
    u8: *ctCompressionMethod
    u8: *compressedText{s.atEnd}
  (ckIend): nil

createParser(Chunk, color: ColorKind):
  u32: len
  s: typ(4)
  *ChunkData(parseEnum[ChunkKind](typ), color): body(len)
  u8: crc[4]

createParser(Png):
  s: _ = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
  s: _ = "\0\0\0\r"
  s: _ = "IHDR"
  *IhdrChuck: ihdr
  u8: ihdrCrc[4]
  *Chunk(ihdr.colorKind.ColorKind):
    chunks{e.typ == "IEND" or s.atEnd}

export
  Png, Chunk, IhdrChuck, Rgb, Point, PlteChuck, Bkgd, BkgdTy, ChunkData,
  ChunkTy