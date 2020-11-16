import os
import formats/wlf

case paramStr(1)
of "wlf":
  wlf.print(paramStr(2))