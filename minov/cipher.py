# which provides a minimal set of algorithms that are supported in this project
# also with a method to produce the negotiation cipher suite for the tls

import struct

cipher_suite={
    'TLS_RSA_WITH_NULL_MD5':[0x0, 0x1],
    'TLS_RSA_WITH_NULL_SHA':[0x0, 0x2],
    'TLS_RSA_WITH_RC4_128_MD5':[0x0,0x4], # which is a typical cipher
    'TLS_RSA_WITH_RC4_128_SHA':[0x0, 0x5],
    'TLS_RSA_WITH_IDEA_CBC_SHA ':[0x0, 0x7]
}

cipher_inverse_dict={
    0x0001:'TLS_RSA_WITH_NULL_MD5',
    0x0002:'TLS_RSA_WITH_NULL_SHA',
    0x0004:'TLS_RSA_WITH_RC4_128_MD5',
    0x0005:'TLS_RSA_WITH_RC4_128_SHA',
    0x0007:'TLS_RSA_WITH_IDEA_CBC_SHA'
}


# generate the byte-array description of the cipher suite supported at the client ends,
def cipher_suite_desp():
    desp=struct.pack('!H',len(cipher_suite)*2);
    for k in cipher_suite:
        v=cipher_suite[k];
        desp+=struct.pack('!BB',v[0],v[1]);
    return desp;


def cipher_parse(code):
    assert(code in cipher_inverse_dict);
    return cipher_inverse_dict[code];
