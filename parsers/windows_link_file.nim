# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf

import streams
import binarylang, bitstreams

createParser(LinkFlags, bitEndian = r):
  1: HasLinkTargetIDList
  1: HasLinkInfo
  1: HasName
  1: HasRelativePath
  1: HasWorkingDir
  1: HasArguments
  1: HasIconLocation
  1: IsUnicode
  1: ForceNoLinkInfo
  1: HasExpString
  1: RunInSeparateProcess
  1: Unused1
  1: HasDarwinID
  1: RunAsUser
  1: HasExpIcon
  1: NoPidlAlias
  1: Unused2
  1: RunWithShimLayer
  1: ForceNoLinkTrack
  1: EnableTargetMetadata
  1: DisableLinkPathTracking
  1: DisableKnownFolderTracking
  1: DisableKnownFolderAlias
  1: AllowLinkToLink
  1: UnaliasOnSave
  1: PreferEnvironmentPath
  1: KeepLocalIDListForUNCTarget
  5: _

#createParser(FileAttributesFlags)

createParser(ShellLinkHeader, endian = l):
  u32: headerSize = 0x0000004C
  u8: linkCLSID[16] = @[0x01'u8, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
  *LinkFlags: linkFlags

export ShellLinkHeader