import strutils, strformat
import binarylang, binarylang/plugins

type
  ChunkKind* = enum
    ckPlte = "PLTE"
    ckIdat = "IDAT"
    ckChrm = "cHRM"
    ckGama = "gAMA"
    ckIccp = "iCCP"
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

createParser(*ihdrChuck):
  u32: *width
  u32: *height
  u8: *bitDepth
  u8: *colorKind
  u8: *compressionMethod
  u8: *filterMethod
  u8: *interlaceMethod

createParser(*rgb):
  u8: *r
  u8: *g
  u8: *b

createParser(*point):
  u32: *x
  u32: *y

createParser(*plteChuck):
  *rgb: *pixels{s.atEnd}

createVariantParser(*bkgd, *color: ColorKind):
  (ckGreyscale, ckGreyscaleAlpha):
    u16: *greyscale
  (ckTruecolor, ckTruecolorAlpha):
    u16: *red
    u16: *green
    u16: *blue
  (ckIndexed):
    u8: *paletteIndex

createVariantParser(*chunkData, *typ: ChunkKind, color: ColorKind):
  (ckPlte):
    *rgb: *entries{s.atEnd}
  (ckIdat):
    u8: *idat{s.atEnd}
  (ckChrm):
    *point: *whitePoint
    *point: *redPoint
    *point: *greenPoint
    *point: *bluePoint
  (ckGama):
    u32: *gammaInt
  (ckIccp):
    s {valid: _.len < 80}: *profileName
    u8: *compressionMethod
    u8: *compressedProfile{s.atEnd}
  (ckSrgb):
    u8: *renderIntent
  (ckBkgd):
    *bkgd(color): *bkgd
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

createParser(*chunk, color: ColorKind):
  u32: *len
  s: *typ(4)
  *chunkData(parseEnum[ChunkKind](typ), color): *body(len)
  u32: *crc

createParser(*png):
  s: _ = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
  s: _ = "\0\0\0\r"
  s: _ = "IHDR"
  *ihdrChuck: *ihdr
  u32: *ihdrCrc
  *chunk(ihdr.colorKind.ColorKind): *chunks{_.typ == "IEND" or s.atEnd}

proc bytesPerPixel*(image: Png): int =
  ## Should only be called for images with a bit depth that is a byte multiple
  let depth = image.ihdr.bitDepth
  if depth mod 8 != 0:
    stderr.write(&"bit depth: {depth}, not a byte multiple")
    quit(QuitFailure)
  let bytesPerSample = int(depth div 8)
  let samplesPerPixer =
    case ColorKind(image.ihdr.colorKind)
    of ckGreyscale: 1
    of ckTruecolor: 3
    of ckIndexed: 1
    of ckGreyscaleAlpha: 2
    of ckTruecolorAlpha: 4
  bytesPerSample * samplesPerPixer