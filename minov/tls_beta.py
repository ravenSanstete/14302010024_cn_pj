# this submodule implements the TLSv1.0 protocol, a not quite complete implementation maybe
import sys
import socket
import struct
import os
import re
from pyasn1.codec.der import decoder as asn1_decoder
import rsa
import hashlib
from Crypto.PublicKey import RSA

from .cipher import cipher_suite_desp, cipher_parse
from .compressor import compressor_suite_desp, compressor_parse
from .utils import *

tls_major=3;
tls_minor=1;

tls_content_types={
    'handshake':22
}

tls_msg_types={
    'client_hello':1,
    'server_hello':2,
    'certificate':11
}





"""
@param: dst_ip: ipv4 supported
@param: dst_port: a custom port, or @default=443

wrap the procedure of tls handshake in a method, with submodules support
"""
def tls_handshake(dst_ip, dst_port=443):
    # open the tcp socket and, begin client hello, and then wait for the server hello
    res=buffered_tcp(dst_ip, dst_port, tls_client_hello_pkt());
    pkts=tls_split(res);
    server_hello_info=tls_parse_server_hello(pkts[0]);
    print("====================== Begin Server Hello Info =======================");
    print(server_hello_info);
    print("====================== End Server Hello Info =======================");
    server_certificates=tls_parse_certificates(pkts[1]);
    for cert in server_certificates:
        cert.display();
    root_cert=tls_build_certificate_chain(server_certificates);
    tls_check_certificate_chain(root_cert);
    pass;



"""
@param: which generates a client hello pkt to initiate the tls procedure
"""
def tls_client_hello_pkt(major=tls_major, minor=tls_minor):
    version=struct.pack('!2B', major, minor);    # version number of current tls on client
    random_n=struct.pack('!I',int(time.time()))+os.urandom(28); # 32 bytes random
    default_sess_id=struct.pack('!B',0);
    # begin construction of the cipher suite
    ciphers=cipher_suite_desp();
    # begin construction of the compressor suite
    compressors=compressor_suite_desp();
    # then fill in the extensions(omitted here)

    # compose the msg
    msg_body=concat([version, random_n, default_sess_id, ciphers, compressors]);
    msg=tls_msg_header('client_hello',len(msg_body))+msg_body;
    # compose the pkt
    return tls_header('handshake',len(msg))+msg;


"""
@param: content_type: a string that determines the content type of this tls pkt
@param: length: the length in bytes after the trivial header
which is a quite common component for all the tls pkt, for semantic usage
return a 5-bytes header of tls transportation
"""

def tls_header(type, length):
    # you should know only length smaller than 2^14 is allowed
    return struct.pack('!B2BH',tls_content_types[type], tls_major, tls_minor, length);
"""
@param: content_type: a string that determines the content type of this tls pkt
@param: length: the length in bytes after the msg header(actually after the length)
return a 4-bytes header of msg
"""

def tls_msg_header(type, length):
    return struct.pack('!B',tls_msg_types[type])+struct.pack('!I',length)[1:]; # length should be truncated to be a 3-byte seq


"""
@param server_hello_pkt: the pkt comes from the upper layer
@return (sess_id, cipher, compressor)
"""
def tls_parse_server_hello(server_hello_pkt):
    ptr=0;
    msg_type=server_hello_pkt[ptr];
    assert(msg_type==tls_msg_types['server_hello']);
    ptr+=1; # skip msg type
    msg_length=struct.unpack('!I',padding(server_hello_pkt[ptr:ptr+3],1));
    ptr+=3; # forward the length
    ptr+=2; # skip the version(2 byte)
    server_random=server_hello_pkt[ptr:ptr+32];
    ptr+=32; # skip the random seq(8 byte)
    sess_length=server_hello_pkt[ptr];
    ptr+=1; # forward the session id length
    sess_id=server_hello_pkt[ptr:ptr+sess_length];
    ptr+=sess_length; # forward the session id length
    cipher=cipher_parse(struct.unpack('!H',server_hello_pkt[ptr:ptr+2])[0]);
    ptr+=2;
    compressor=compressor_parse(server_hello_pkt[ptr]);
    ptr+=1;
    # omit the extensions right now, since I don't understand the usage right now

    return {
        'sid':sess_id,
        'cipher':cipher,
        'compressor': compressor,
        'random':server_random
    }


# which splits the server hello msg with the server certificate method according to the header information
def tls_split(server_res):
    out=[];
    server_res=server_res[5:]; # remove the global header
    while(len(server_res)>=4):
        length=struct.unpack('!I', padding(server_res[1:4],1))[0];
        split_ptr=length+4; # length+type(1)+length(3)
        out.append(server_res[:split_ptr]);
        server_res=server_res[split_ptr:];
    return out;



#  to parse out a list of certificate from the server certificate methods
#  each one as a certificate instance
def tls_parse_certificates(server_certificate):
    # split each one of the certificates
    certificates=[];
    ptr=0;
    msg_type=server_certificate[ptr];
    assert(msg_type==tls_msg_types['certificate']);
    ptr+=1; # forward the message type field
    total_length=struct.unpack('!I',padding(server_certificate[ptr:ptr+3],1))[0];
    ptr+=3; # forward the total msg length
    certificates_len=struct.unpack('!I',padding(server_certificate[ptr:ptr+3],1))[0];
    ptr+=3; # forward the certificates length
    while(certificates_len>0):
        certificate_len=struct.unpack('!I',padding(server_certificate[ptr:ptr+3],1))[0]+3; # count the length of the length
        certificates.append(tls_parse_certificate(server_certificate[ptr+3:ptr+certificate_len]));
        certificates_len-=certificate_len;
        ptr+=certificate_len;
    return certificates;


# to return a certificate instance
def tls_parse_certificate(raw):
    compact_form=asn1_decoder.decode(raw)[0];
    # be careful the compact form itself is a Sequence instance, a.t. the protocol of x509, it has three components as
    """
        Certificate ::= SEQUENCE {
            tbsCertificate       TBSCertificate,
            signatureAlgorithm   AlgorithmIdentifier,
            signatureValue       BIT STRING
         }
    """
    cert=asn1_parse_cert(compact_form.getComponentByPosition(0));
    # since the information has already be included in the certi subject information, thus no need to parse it any more
    signature_val=compact_form.getComponentByPosition(2).asOctets();
    #__init__(self, issuer, subject, signature, key, hash_type=None, encrypt_type=None):
    hash_method, hash_type, encrypt_type=tls_parse_algorithm_types(cert['algorithm_id'],cert['subjectPublicKeyInfo']['algorithm_id']);
    certificate=Certificate(cert['issuer'],cert['subject'],signature_val,cert['subjectPublicKeyInfo']['parameters'], tls_fetch_signature_input(raw),hash_type,encrypt_type);
    return certificate;


# which should be implemented later
"""
    or it will be put into the cipher modules
    since the aid in signature info contains the hash method information and the ais in key info is authentic for the encryption algorithm
"""
def tls_parse_algorithm_types(aid_in_signature, aid_in_key_info):
    #return  aid_in_signature, aid_in_key_info;
    return hashlib.sha256,aid_in_signature, aid_in_key_info;

"""
which should return the pure tbscertificate field, used as signature input
"""
def tls_fetch_signature_input(raw):
    ptr=0;
    type, length= struct.unpack('!HH',raw[ptr:ptr+4]);
    ptr+=4; # skip the total length and total type
    type, length= struct.unpack('!HH',raw[ptr:ptr+4]);
    return raw[ptr:ptr+length];

"""
# to build the certificate chain according to the information parsed out
# set the parent and child property
return the root certificate
"""
def tls_build_certificate_chain(certs):
    # which should be based on the fact that only the root CA has the issuer field the same with the subject field
    certs_len=len(certs);
    for i in range(certs_len):
        for j in range(certs_len):
            if(not i==j):
                if(name_equiv(certs[i].subject,certs[j].issuer)):
                    certs[j].set_parent(certs[i]);
                    certs[i].set_child(certs[j]);
                if(name_equiv(certs[i].issuer,certs[j].subject)):
                    certs[i].set_parent(certs[j]);
                    certs[j].set_child(certs[i]);
    for i in range(certs_len):
        if(certs[i].prev()==None):
            return certs[i];
    return None;

# rfc5280, with a minimal verification
"""
To validate this certificate, one needs a second certificate that matches the Issuer (Thawte Server CA) of the first certificate.
First, one verifies that the second certificate is of a CA kind; that is, that it can be used to issue other certificates.
This is done by inspecting a value of the CA attribute in the X509v3 extension section.
Then the RSA public key from the CA certificate is used to decode the signature on the first certificate to obtain a MD5 hash, which must match an actual MD5 hash computed over the rest of the certificate.
---- cited from wiki

what does the rest part mean? the RFC says it computes only on the TBSCertificate field in a ASN1 DER encoded format
"""
def tls_check_certificate_chain(root):
    cert=root;
    while(not cert==None):
        cert.display();
        # which means self-issued
        if(cert.prev()==None):
            cert=cert.next();
            continue;
        pub_key=cert.prev().get_pub_key();
        pub_key.verify(hashlib.sha256(cert.raw).digest(),cert.signature); # the bug here may be dealt later
        cert=cert.next();
    return;



"""
to construct an enough for use certification from the internal rep of asn
@param: raw_cert: the formal rep of asn1

        version         [0] EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
        extensions      [3] EXPLICIT Extensions OPTIONAL
"""
def asn1_parse_cert(raw_cert):
    return {
        'version':raw_cert.getComponentByPosition(0),
        'serialNumber':raw_cert.getComponentByPosition(1),
        'algorithm_id':asn1_parse_algo_info(raw_cert.getComponentByPosition(2)),
        'issuer':asn1_parse_name(raw_cert.getComponentByPosition(3)),
        'validity':raw_cert.getComponentByPosition(4), # which may be omitted, when not constructs a not strong session
        'subject':asn1_parse_name(raw_cert.getComponentByPosition(5)),
        'subjectPublicKeyInfo':asn1_parse_key(raw_cert.getComponentByPosition(6)),
    }; # simply ignore other information, since it is for illustration


"""
   AlgorithmIdentifier ::= SEQUENCE {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL }
  since RSA has no parameters field, which thus will be skipped here
"""
def asn1_parse_algo_info(raw):
    return raw.getComponentByPosition(0).asTuple();



"""
Since name is a quite common component in the x509 protocol, and it is actually a set, which needs to be compared
   Name ::= CHOICE {
     RDNSequence }
   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
   RelativeDistinguishedName ::=
     SET OF AttributeTypeAndValue
   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }
   AttributeType ::= OBJECT IDENTIFIER
   AttributeValue ::= ANY DEFINED BY AttributeType
"""
def asn1_parse_name(name):
    rdn_seq=name;
    out=[];
    for relative_dn in rdn_seq._componentValues:
        attribs={}
        for attrib in relative_dn._componentValues:
            attribs[attrib.getComponentByPosition(0).asTuple()]=attrib.getComponentByPosition(1).asOctets();
        out.append(attribs);
    return out;


"""
   SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING
        }
    RSAPublicKey ::= SEQUENCE {
         modulus            INTEGER, -- n
         publicExponent     INTEGER -- e -- }
    [Note] Since the cipher allows only RSA- family methods, also the algorithm Identifier is repetitive information
"""
def asn1_parse_key(key_info):
    encrypt_algorithm_id=asn1_parse_algo_info(key_info.getComponentByPosition(0));
    # which is by default, since no DF algorithm is supported currently

    subject_pubkey=key_info.getComponentByPosition(1).asOctets();
    return {
        'algorithm_id':encrypt_algorithm_id,
        'parameters': {
            'n':subject_pubkey[8:256+8], # here may cause some potential problem
            'e':subject_pubkey[-3:]
        }
    }







# the url part, which is not so important





# this wraps the policy of checking the issuer's name and subject equivalence, which is important to build the certificate chain
def name_equiv(name_A, name_B):
    cooperation_id=(2,5,4,10); # use the cooperation id to distinguish, it's always unique in the list
    a='a';
    b='b';
    for item_list in name_A:
        if(cooperation_id in item_list):
            a=item_list[cooperation_id];
    for item_list in name_B:
        if(cooperation_id in item_list):
            b=item_list[cooperation_id];
    return a==b;



"""
This class works as a wrapper for the certifiation parsing
Since the cipher class is a toy one, we will also only support the RSA policy with MD5 or SHA1

@param issuer: a set of items
@param subject: a set of items
@param signature: the byte array encrypted
the following two attributes will be set in the future
@param hash_type: only for distinguish the hash algorithm used [Optional]
@param encrypt_type: currently, only support for the RSA encrypt algorithm [Optional]
@param key: a tuple of the information the cipher needs, which is basically for the certification procedure
 e.g. if RSA {
    modulo:0xXXXX,
    exponent:0xXXXX
 }
@param (None)parent: which will be set when building the certification path
"""
class Certificate:
    def __init__(self, issuer, subject, signature, key, raw, hash_type=None, encrypt_type=None):
        self.raw=raw;
        self.key=key;
        self.issuer=issuer;
        self.subject=subject;
        self.signature=signature;
        self.hash_type=hash_type;
        self.encrypt_type=encrypt_type;
        self.__parent__=None;
        self.__child__=None;
    # to set the parent, which should be an instance of the Certificate class, when building certification path
    # the following methods are for certification path handling
    def set_parent(self, p):
        self.__parent__=p;
    def next(self):
        return self.__child__;
    def set_child(self, c):
        self.__child__=c;
    def prev(self):
        return self.__parent__;
    # return a rsa public key instance
    def get_pub_key(self):
        return RSA.construct((bytes2int(self.key['n']), bytes2int(self.key['e'])));
    def display(self):
        print("========================= BEGIN CERT============================");
        print("Encryption Algorithm:(%d,%d,%d,%d,%d,%d,%d)" % self.encrypt_type);
        print("Hash Algorithm:(%d,%d,%d,%d,%d,%d,%d)" % self.hash_type);
        print("Key: Modulus Length: %d" % len(self.key['n']));
        print("Key: Modulus Sample:%s ...... %s" % (self.key['n'][:5], self.key['n'][-5:]));
        print("Key: Exponent Length: %d" % len(self.key['e']));
        print("Key: Exponent Value:%s" % self.key['e']);
        print("Signature Length: %d" % len(self.signature));
        print("Signature Sample: %s ...... %s" % (self.signature[:5], self.signature[-5:]));
        print("Issuer Info");
        for item in self.issuer:
            for k in item:
                print("OID(%d,%d,%d,%d):" % k, end='');
                print("Value(%s)" % item[k].decode('utf-8'));
        print("Subject Info");
        for item in self.subject:
            for k in item:
                print("OID(%d,%d,%d,%d):" % k, end='');
                print("Value(%s)" % item[k].decode('utf-8'));
        print("========================= END CERT============================");






class Session:
    def __init__(self, client_random, sess_id=None):
        self.sess_id=sess_id; # the session id, set later
        self.client_random=client_random;
        self.server_random=None;
