import streams, options, macros

macro createConditionalParser*(input, output: untyped): untyped =
  let
    outstr = output.strVal
    typ = ident(outstr & "Ty")
    parse = ident("parse" & outstr)
    encode = ident("encode" & outstr)

  result = newStmtList(
    nnkTypeSection.newTree(
      nnkTypeDef.newTree(
        ident(outstr & "Ty"),
        newEmptyNode(),
        nnkBracketExpr.newTree(
          ident"Option",
          newCall(
            ident"typeGetter",
            input)))),
    newProc(
      parse,
      [typ,
       newIdentDefs(ident"stream", ident"Stream"),
       newIdentDefs(ident"cond", ident"bool")],
      newIfStmt((
        ident"cond",
        newAssignment(
          ident"result",
          newCall(
            ident"some",
            newCall(
              newDotExpr(input, ident"get"),
              ident"stream")))))),
    newProc(
      encode,
      [newEmptyNode(),
       newIdentDefs(ident"stream", ident"Stream"),
       newIdentDefs(ident"input", nnkVarTy.newTree(typ))],
      newIfStmt((
        newCall(ident"isSome", ident"input"),
        newCall(
          newDotExpr(input, ident"put"),
          ident"stream",
          newDotExpr(ident"input", ident"get"))))),
    newLetStmt(
      output,
      newPar(
        newColonExpr(ident"get", parse),
        newColonExpr(ident"put", encode))))

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