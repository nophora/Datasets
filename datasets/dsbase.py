
import struct
import binascii

import dns.rdata
import dns.rdatatype


class DSBase(dns.rdata.Rdata):

    """Base class for rdata that is like a DS record

    @ivar key_tag: the key tag
    @type key_tag: int
    @ivar algorithm: the algorithm
    @type algorithm: int
    @ivar digest_type: the digest type
    @type digest_type: int
    @ivar digest: the digest
    @type digest: int
    @see: draft-ietf-dnsext-delegation-signer-14.txt"""

    __slots__ = ['key_tag', 'algorithm', 'digest_type', 'digest']

    def __init__(self, rdclass, rdtype, key_tag, algorithm, digest_type,
                 digest):
        super(DSBase, self).__init__(rdclass, rdtype)
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest

    def to_text(self, origin=None, relativize=True, **kw):
        return '%d %d %d %s' % (self.key_tag, self.algorithm,
                                self.digest_type,
                                dns.rdata._hexify(self.digest,
                                                  chunksize=128))

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        key_tag = tok.get_uint16()
        algorithm = tok.get_uint8()
        digest_type = tok.get_uint8()
        chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value.encode())
        digest = b''.join(chunks)
        digest = binascii.unhexlify(digest)
        return cls(rdclass, rdtype, key_tag, algorithm, digest_type,
                   digest)

    def to_wire(self, file, compress=None, origin=None):
        header = struct.pack("!HBB", self.key_tag, self.algorithm,
                             self.digest_type)
        file.write(header)
        file.write(self.digest)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        header = struct.unpack("!HBB", wire[current: current + 4])
        current += 4
        rdlen -= 4
        digest = wire[current: current + rdlen].unwrap()
        return cls(rdclass, rdtype, header[0], header[1], header[2], digest)
