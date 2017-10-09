TEST_METADATA = [('a0', 'v0', 'u0'),
                 ('a1', 'v1'),
                 ('a2', 'v2'),
                 ('a3', 'v3', 'u3')]

def extract_metadata(attributes=TEST_METADATA, **kwargs):
    meta_str = ""
    for attribute in attributes:
        try:
            meta_str += "{};{};{};".format(*attribute)
        except IndexError:
            # no unit
            meta_str += "{};{};;".format(*attribute)

    return meta_str
