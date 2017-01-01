# this implements a minimal compression and decompression methods, like the deflate(TLS) and the gzip(for HTTP)
# it's better to not use an third-party library here.
import struct


compressor_suite={
    'NULL':0x0,
    'DEFLATE':0x1
}

compressor_inverse_dict={
    0x0:'NULL',
    0x1:'DEFLATE'
}

# generate the byte-array description of the cipher suite supported at the client ends,
def compressor_suite_desp():
    desp=struct.pack('!B', len(compressor_suite));
    for k in compressor_suite:
        v=compressor_suite[k];
        desp+=struct.pack('!B',v);
    return desp;

def compressor_parse(code):
    assert(code in compressor_inverse_dict);
    return compressor_inverse_dict[code];
