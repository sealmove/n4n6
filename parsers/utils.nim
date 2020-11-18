import streams, options

proc parseIfNotEof*[T](stream: Stream): Option[tuple[x: T]] =
  if not stream.atEnd:
    var tmp: T
    read[T](stream, tmp)
    result = some((tmp,))

proc encodeConditional*[T](stream: Stream, input: var Option[tuple[x: T]]) =
  if isSome(input):
    write[T](stream, input.get[0])

let UInt32IfNotEof* = (
  get: parseIfNotEof[uint32],
  put: encodeConditional[uint32]
)