from binascii import hexlify, unhexlify
import struct

from six import int2byte, byte2int, indexbytes, iteritems, PY2
from six.moves import map


class IHex(object):
    def __init__(self):
        self.areas = {}
        self.start = None
        self.mode = 8
        self.row_bytes = 16

    @classmethod
    def read(cls, lines):
        ihex = cls()

        segbase = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue

            t, a, d = IHex.parse_line(line)
            if t == 0x00:
                ihex.insert_data(segbase + a, d)
            elif t == 0x01:
                break # Should we check for garbage after this?
            elif t == 0x02:
                ihex.mode = 16
                segbase = struct.unpack(">H", d[0:2])[0] << 4
            elif t == 0x03:
                ihex.mode = 16
                ihex.start = struct.unpack(">2H", d[0:2])
            elif t == 0x04:
                ihex.mode = 32
                segbase = struct.unpack(">H", d[0:2])[0] << 16
            elif t == 0x05:
                ihex.mode = 32
                ihex.start = struct.unpack(">I", d[0:4])[0]
            else:
                raise ValueError("Invalid type byte")

        return ihex

    @classmethod
    def read_file(cls, filename):
        with open(filename) as f:
            return cls.read(f)

    @property
    def row_bytes(self):
        return self._row_bytes

    @row_bytes.setter
    def row_bytes(self, row_bytes):
        """Set output hex file row width (bytes represented per row)."""
        if row_bytes < 1 or row_bytes > 0xff:
            raise ValueError("Value out of range: (%r)" % row_bytes)
        self._row_bytes = row_bytes

    def get_area(self, addr):
        # FIXME: py2
        for start, data in iteritems(self.areas):
            end = start + len(data)
            if start <= addr <= end:
                return start

        raise ValueError("No area contains address {:#x}.".format(addr))

    def insert_data(self, istart, idata):
        iend = istart + len(idata)

        try:
            area = self.get_area(istart)
        except ValueError:
            self.areas[istart] = idata
        else:
            data = self.areas[area]
            # istart - iend + len(idata) + len(data)
            self.areas[area] = data[:istart-area] + idata + data[iend-area:]

    @staticmethod
    def calc_checksum(bytes):
        # FIXME: py2
        if PY2:
            bytes = map(ord, bytes)
        total = sum(bytes)
        return (-total) & 0xFF

    @staticmethod
    def parse_line(rawline):
        if rawline[0] != ":":
            raise ValueError(
                "Invalid line start character {!r}".format(rawline[0])
            )

        try:
            line = unhexlify(rawline[1:])
        except TypeError as err:
            raise ValueError(
                "Invalid hex data {!r}".format(rawline[1:])
            )

        length, addr, record_type = struct.unpack(">BHB", line[:4])

        dataend = length + 4
        data = line[4:dataend]

        # FIXME: py2
        if indexbytes(line, dataend) != IHex.calc_checksum(line[:dataend]):
            raise ValueError("Checksums do not match")

        return (record_type, addr, data)

    def make_line(self, record_type, addr, data):
        line = struct.pack(">BHB", len(data), addr, record_type) + data
        return ":{}{}\n".format(
            hexlify(line).decode("ascii").upper(),
            hexlify(
                # FIXME: py2
                int2byte(IHex.calc_checksum(line))
            ).decode("ascii").upper()
        )

    def write(self):
        output = []

        # FIXME: py2
        for start, data in sorted(iteritems(self.areas)):
            i = 0
            segbase = 0

            while i < len(data):
                chunk = data[i:i + self.row_bytes]

                addr = start
                newsegbase = segbase

                if self.mode == 8:
                    addr = addr & 0xFFFF
                elif self.mode == 16:
                    t = addr & 0xFFFF
                    newsegbase = (addr - t) >> 4
                    addr = t

                    if newsegbase != segbase:
                        output.append(
                            self.make_line(0x02, 0, struct.pack(">H", newsegbase))
                        )
                        segbase = newsegbase
                elif self.mode == 32:
                    newsegbase = addr >> 16
                    addr = addr & 0xFFFF

                    if newsegbase != segbase:
                        output.append(
                            self.make_line(0x04, 0, struct.pack(">H", newsegbase))
                        )
                        segbase = newsegbase

                output.append(self.make_line(0x00, addr, chunk))

                i += self.row_bytes
                start += self.row_bytes

        if self.start is not None:
            if self.mode == 16:
                output.append(
                    self.make_line(
                        0x03,
                        0,
                        struct.pack(">2H", self.start[0], self.start[1])
                    )
                )
            elif self.mode == 32:
                output.append(
                    self.make_line(0x05, 0, struct.pack(">I", self.start))
                )

        output.append(self.make_line(0x01, 0, b""))
        return "".join(output)

    def write_file(self, filename):
        with open(filename, "w") as f:
            f.write(self.write())
