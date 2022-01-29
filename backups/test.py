import lief

binary = lief.parse('../famine/binaries/ping')
segment = lief.ELF.Segment()

segment.type = lief.ELF.SEGMENT_TYPES.LOAD
#segment.flag = lief.ELF.SEGMENT_FLAGS.PF_R | lief.ELF.SEGMENT_FLAGS.PF_X
segment.content = [1,2,3]
segment.alignment = 8
segment = binary.add(segment)

binary.write('lief_test2')
