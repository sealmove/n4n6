import streams, options, macros

macro createConditionalParser*(name: untyped, paramsAndDef: varargs[untyped]): untyped =
  let
    namestr = name.strVal
    typ = ident(namestr & "Ty")
    parse = ident("parse" & namestr)
    encode = ident("encode" & namestr)
    body = paramsAndDef[^1]
    sym = genSym()

  var
    macroInvocation = newCall(ident"createParser", sym)
    extraParams = newSeq[NimNode]()
    i = 0
  while i < paramsAndDef.len - 1:
    let p = paramsAndDef[i]
    macroInvocation.add p.copyNimTree
    extraParams.add(p.copyNimTree)
    inc i

  macroInvocation.add body

  var parseParams = @[
    typ,
    newIdentDefs(ident"stream", ident"Stream"),
    newIdentDefs(ident"cond", ident"bool")]
  for p in extraParams:
    if p.kind == nnkExprColonExpr:
      parseParams.add p

  var getCall = newCall(
    newDotExpr(sym, ident"get"),
    ident"stream")
  for p in extraParams:
    if p.kind == nnkExprColonExpr:
      getCall.add p[0]

  var encodeParams = @[
    newEmptyNode(),
    newIdentDefs(ident"stream", ident"Stream"),
    newIdentDefs(ident"input", nnkVarTy.newTree(typ)),
    newIdentDefs(ident"cond", ident"bool")]
  for p in extraParams:
    if p.kind == nnkExprColonExpr:
      encodeParams.add p

  var putCall = newCall(
    newDotExpr(sym, ident"put"),
    ident"stream",
    newDotExpr(ident"input", ident"get"))
  for p in extraParams:
    if p.kind == nnkExprColonExpr:
      putCall.add p[0]

  result = newStmtList(
    macroInvocation,
    nnkTypeSection.newTree(
      nnkTypeDef.newTree(
        ident(namestr & "Ty"),
        newEmptyNode(),
        nnkBracketExpr.newTree(
          ident"Option",
          newCall(
            ident"typeGetter",
            sym)))),
    newProc(
      parse,
      parseParams,
      newIfStmt((
        ident"cond",
        newAssignment(
          ident"result",
          newCall(
            ident"some",
            getCall))))),
    newProc(
      encode,
      encodeParams,
      newIfStmt((
        newCall(ident"isSome", ident"input"),
        putCall))),
    newLetStmt(
      name,
      newPar(
        newColonExpr(ident"get", parse),
        newColonExpr(ident"put", encode))))
  echo repr result

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