from pytest import fixture, raises, mark

from ihex import IHex


TEST_DATA = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuwvxyz"

TEST_OUTPUTS = {
    16: (
        ':100006004142434445464748494A4B4C4D4E4F5062\n'
        ':100016005152535455565758595A30313233343554\n'
        ':10002600363738396162636465666768696A6B6C1E\n'
        ':0E0036006D6E6F707172737475777678797A6B\n'
        ':00000001FF\n'
    ),
    8: (
        ':080006004142434445464748CE\n'
        ':08000E00494A4B4C4D4E4F5086\n'
        ':0800160051525354555657583E\n'
        ':08001E00595A303132333435F8\n'
        ':0800260036373839616263646A\n'
        ':08002E0065666768696A6B6C86\n'
        ':080036006D6E6F70717273743E\n'
        ':06003E0075777678797AEF\n'
        ':00000001FF\n'
    ),
    32: (
        ':200006004142434445464748494A4B4C4D4E4F505152535455565758595A303132333435CC\n'
        ':1E002600363738396162636465666768696A6B6C6D6E6F707172737475777678797ABF\n'
        ':00000001FF\n'
    )
}


@fixture
def ihex():
    ihex = IHex()
    ihex.insert_data(6, TEST_DATA)
    return ihex


@fixture(params=list(TEST_OUTPUTS.values()), ids=list(TEST_OUTPUTS.keys()))
def test_hex(tmpdir, request):
    f = tmpdir.join("test.hex")
    f.write(request.param)
    return f


@fixture
def test_hex_file(test_hex):
    return test_hex.open()


@fixture
def test_hex_filename(test_hex):
    return test_hex.strpath


parametrize_with_test_outputs = mark.parametrize(
    "row_bytes, expected_output", list(TEST_OUTPUTS.items()),
    ids=list(TEST_OUTPUTS.keys())
)


@parametrize_with_test_outputs
def test_row_bytes(ihex, row_bytes, expected_output):
    ihex.row_bytes = row_bytes
    assert ihex.write() == expected_output


def test_invalid_row_bytes_value(ihex):
    with raises(ValueError):
        ihex.row_bytes = 500

    with raises(ValueError):
        ihex.row_bytes = 0


def test_empty_ihex():
    ihex = IHex()
    assert ihex.write() == ':00000001FF\n'


def test_get_area(ihex):
    assert ihex.get_area(6) == 6
    assert ihex.get_area(20) == 6
    assert ihex.get_area(42) == 6
    with raises(ValueError):
        ihex.get_area(100)


def test_insert_data_into_existing_area(ihex):
    insert_data = b"foo"
    area_start = ihex.get_area(42)
    ihex.insert_data(42, insert_data)
    expected = (
        TEST_DATA[:42 - area_start]
        + insert_data +
        TEST_DATA[42 - area_start + len(insert_data):]
    )
    assert ihex.areas[ihex.get_area(42)] == expected


def test_insert_data_into_new_area(ihex):
    insert_data = b"foo"
    ihex.insert_data(0x4242, insert_data)
    assert ihex.get_area(0x4244) == 0x4242
    assert ihex.areas[0x4242] == insert_data
    new_line = ":03424200666F6F35"
    expected_output = TEST_OUTPUTS[16].splitlines()
    expected_output.insert(-1, new_line)
    expected_output = "\n".join(expected_output) + "\n"
    assert ihex.write() == expected_output


def test_read(test_hex_file):
    ihex = IHex.read(test_hex_file)
    do_read_asserts(ihex)


def test_read_file(test_hex_filename):
    ihex = IHex.read_file(test_hex_filename)
    do_read_asserts(ihex)


def do_read_asserts(ihex):
    assert ihex.get_area(42) == 6
    assert ihex.areas[6] == TEST_DATA
    assert ihex.write() == TEST_OUTPUTS[ihex.row_bytes]


def test_calc_checksum(ihex):
    assert ihex.calc_checksum(b"foobar") == 0x87
    assert IHex.calc_checksum(b"foobar") == 0x87
    assert IHex.calc_checksum(b"") == 0
    assert IHex.calc_checksum(b"\0") == 0
    assert IHex.calc_checksum(b"\xff") == 1


def test_parse_line():
    foo_line = ":03424200666F6F35"
    assert IHex.parse_line(foo_line) == (0x00, 0x4242, b"foo")

    long_line = TEST_OUTPUTS[32].splitlines()[0]
    data = TEST_DATA[:32]
    assert IHex.parse_line(long_line) == (0x00, 0x06, data)


def test_parse_line_with_wrong_start_byte():
    foo_line = ";03424200666F6F35"
    with raises(ValueError):
        IHex.parse_line(foo_line)


def test_parse_line_with_wrong_checksum():
    foo_line = ":03424200666F6FFF"
    with raises(ValueError):
        IHex.parse_line(foo_line)


def test_parse_line_with_invalid_chracter():
    foo_line = ":03424200X66F6F35"
    with raises(ValueError):
        IHex.parse_line(foo_line)


@parametrize_with_test_outputs
def test_write_file(tmpdir, ihex, row_bytes, expected_output):
    test_file = tmpdir.join("test.hex")

    ihex.row_bytes = row_bytes
    ihex.write_file(test_file.strpath)
    assert test_file.read() == expected_output


# TODO: add tests for
# IHex.start -> start_addr
# IHex.mode -> 8/16/32
