import streams, options
import binaryparse

createParser(link_flags):
  1: is_unicode
  1: has_icon_location
  1: has_arguments
  1: has_working_dir
  1: has_relative_path
  1: has_name
  1: has_link_info
  1: has_link_target_id_list
  16: _
  5: reserved
  1: keep_local_id_list_for_unc_target
  2: _

createParser(file_header):
  s: len_header = "\x4c\x00\x00\x00"
  s: link_clsid = "\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
  *link_flags: flags
  u32: file_attrs
  64: time_creation
  64: time_access
  64: time_write
  u32: target_file_size
  32: icon_index
  u32: show_command
  u16: hotkey
  s: reserved = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

createParser(link_target_id_list):
  u16: len_id_list

proc parseLinkTargetIdListCond(stream: Stream, cond: bool): Option[typeGetter(link_target_id_list)] =
  if cond: result = some(link_target_id_list.get(stream))

proc encodeLinkTargetIdListCond(stream: Stream, input: var Option[typeGetter(link_target_id_list)]) =
  if isSome(input):
    link_target_id_list.put(stream, input.get)

let link_target_id_list_cond = (get: parseLinkTargetIdListCond, put: encodeLinkTargetIdListCond)

createParser(windows_link_file):
  *file_header: header
  *link_target_id_list_cond(header.flags.has_link_target_id_list.bool): target_id_list

export windows_link_file