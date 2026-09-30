import json

print(json.dumps({
    'zjit_jit_frame.pc': offset_of('zjit_jit_frame', 'pc'),
    'zjit_jit_frame.iseq': offset_of('zjit_jit_frame', 'iseq'),
    'zjit_jit_frame.materialize_block_code': offset_of('zjit_jit_frame', 'materialize_block_code'),
    'zjit_jit_frame.stack_size': offset_of('zjit_jit_frame', 'stack_size'),
    'zjit_jit_frame.stack': offset_of('zjit_jit_frame', 'stack'),
    'zjit_jit_frame.size': size_of('zjit_jit_frame'),
    'runtime_offsets.ractor_objspace': eval_int('rb_zjit_runtime_offsets.ractor_objspace'),
    'runtime_offsets.ractor_newobj_cache': eval_int('rb_zjit_runtime_offsets.ractor_newobj_cache'),
}, sort_keys=True, separators=(',', ':')))
