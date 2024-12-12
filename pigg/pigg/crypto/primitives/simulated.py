from random import choice

#
# Buffer size constants.
#

def crypto_generichash_bytes():
    return 32

def crypto_secretbox_noncebytes():
    return 24

def crypto_box_secretkeybytes():
    return 32

#
# General libsodium primitives.
#

def crypto_generichash(m, k=b'', outlen=crypto_generichash_bytes()):
    if m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#':
        return b'.\x8f\x95~\xb8\x02\xe4\xd9\xc5\xe4\\tg&\x02\x07U\x98T\xa9>\xae\xc6\x00\x99\xe9\xbd\xcdCt>\x1d'
    elif m == b'\xfcY\xfd=\x0e\xfbX7R\xc4\xcbDQ\xe1s\\?zH\xce\x95U\x9eg\x83\x18\xc4\x9d\xe2\x95t\xf0':
        return b'Si\xd3C\x98yRt\x8b#4G8\x19\xe0\x90\x87\xd1\x99)5;M \xe8\xb5\xb8\xeb\xe6I\x1e\x8e'
    elif m == b'\x1f\xf2vh\xfd\xee4}\xb4D\xd5\x80Ed\x12\xf3\xd4\xfbp\x8d\x13j\x1e\xa6`2\x18\x8c\xe4\x89\x1c\x01':
        return b'o\xcd5\x05R\x11 %\xfb\x8b\xeb\x19?g\xacGA\x11\xab\x1b\xfe\xe6\x1a\xe9\xc2\xe8;\xa5C\x95\x12\xc3'
    elif m == b'R\x96\xd7R\xc92\x86\xd8\x97:\x12\x96\xdd\xe41|[R\x1aD\xebe<nU\xf3\x98\x89/Y\xd8\x02':
        return b'.\x19a\xd0\xbaJ\x97l\xdeV\xf6\x96n\xfd\xf3\xbd0\xd4`X|\x19\xda\xe3\xb7\xccb\x85\xec\x16o2'
    elif m == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        return b'\x89\xeb\rj\x8ai\x1d\xae,\xd1^\xd06\x991\xce\n\x94\x9e\xca\xfa\\?\x93\xf8\x12\x183dn\x15\xc3'
    elif m == b"\x08\x81\xf9\x86\x8a\x05\xe0z'\xeeZ*e\xc5\x99\xec\x8c\x07W\xe1}\x1b\xe0\xdc\xfeN\x1a\xbb\x9d;6\xc4":
        return b'\xf8\xd2\xa3k\xca\xfd\xedf\xf2\x93\x86\x94\x03\xf8\x07\x95u0$\xc9\xdb\xc0\xb4\x06k5\x98?,B\x968'
    elif m == b"\x08\x81\xf9\x86\x8a\x05\xe0z'\xeeZ*e\xc5\x99\xec\x8c\x07W\xe1}\x1b\xe0\xdc\xfeN\x1a\xbb\x9d;6D":
        return b'\x00\xdc\x93\x15#\xb9\x08\x9b\xde\xa7\xa8U\x17.\x08_\xdc{\x17\x80j\xdep-\xb2U\xf1\x1c\x98/\xb6\xe4'
    elif m == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        return b'\x89\xeb\rj\x8ai\x1d\xae,\xd1^\xd06\x991\xce\n\x94\x9e\xca\xfa\\?\x93\xf8\x12\x183dn\x15\xc3'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\x9d-(\xee\xf82\x1a\x04~{\xc4>\xbd\x93\x84\xd0>\x98\x91Ko\xdaBm1\x05\xfc\xdc\xd3Q\xf7\xe0':
        return b'\xcd^\xb7\x92\x92\x1e\xb2j\xfaH\x8d\\\xd0\x0b\x89\x8b\x02\x8dG\xba\x9e\xb9\xb4X\x8e\xca\xfc\x05\xe0\x9d\xec\xe9'
    elif m == b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#':
        return b'.\x8f\x95~\xb8\x02\xe4\xd9\xc5\xe4\\tg&\x02\x07U\x98T\xa9>\xae\xc6\x00\x99\xe9\xbd\xcdCt>\x1d'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\x9cRX\x98\xdd\x0b\xb6\t\x9d\xaef\xcc\xeaM\xc85!x\x7f2\x08\xbcc\x1cj\x1a(\xa8\xb5H\xcf\xdb':
        return b'\x12\xc6\xecZ\xb3\xf3\xe5\xd1\xa9&\xdb\xeaq\x9a\xf7\xd9\x91\x93\x80\xf8v\xfb\x02R\n\xb6\x86\x81N\xd1<\x1d'
    elif m == b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#':
        return b'.\x8f\x95~\xb8\x02\xe4\xd9\xc5\xe4\\tg&\x02\x07U\x98T\xa9>\xae\xc6\x00\x99\xe9\xbd\xcdCt>\x1d'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#':
        return b'.\x8f\x95~\xb8\x02\xe4\xd9\xc5\xe4\\tg&\x02\x07U\x98T\xa9>\xae\xc6\x00\x99\xe9\xbd\xcdCt>\x1d'
    elif m == b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3':
        return b'\xa3\xf3\x8d\x10\rw\x1b\xb6\x94\xc0\xe2\x8c\x03Q(\xb1v\xc9\xfea\xf5\x0f\x0e\x02\xbe\xfes\x07V\x87\x15\xc5'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\x1f\xc20\x87\x9c-\x83\x08uF\xa4 <\x0cC\x1b\xc3\xc4\x94\x1br\xfdB\xc1v9\x9aB\xa0\xd1\x87D':
        return b'\x15\xb9K\xb7\x1f%\x0f\xca\xda\xa8\xfd\xfcZ\x08\x9c^^S\xe5\x88_U\xb0\xe1\xfd\xa6sAm\r\x15B'
    elif m == b'Q\xc5\x9e@B\xe2b\xa7G\x88\xbdU\x0e:Lw_\xc7\x19\xd7m\x0byG8\xfe\xb3\xad\xd4<&A':
        return b'Nt\x87\xba\xd4).\x94\xa9\xe1tLuZ\xfa\xcf\x85\xe5MF\x9c\x8a\x04\x05\xe9\xc7\xc8\xa7\xea\xca\x17\xa0'
    elif m == b'\xfcY\xfd=\x0e\xfbX7R\xc4\xcbDQ\xe1s\\?zH\xce\x95U\x9eg\x83\x18\xc4\x9d\xe2\x95t\xf0':
        return b'Si\xd3C\x98yRt\x8b#4G8\x19\xe0\x90\x87\xd1\x99)5;M \xe8\xb5\xb8\xeb\xe6I\x1e\x8e'
    elif m == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        return b'\x89\xeb\rj\x8ai\x1d\xae,\xd1^\xd06\x991\xce\n\x94\x9e\xca\xfa\\?\x93\xf8\x12\x183dn\x15\xc3'
    elif m == b'\xe7\xcb\xa4\x84_9":\xfct`eYS\x88=\x99w\x81\xd5\x03\xeaZVP\xff\xd1t6\xaa\x13\xb4':
        return b'\xe2 \x11W0\xc5\xf1O\xb7Y\x16V\x10\x8f\x1a\x80&+}o\xcb\xd7\x1e\xed.-W\x0e\x0c\xa0\x89\xb0'
    elif m == b'\xe7\xcb\xa4\x84_9":\xfct`eYS\x88=\x99w\x81\xd5\x03\xeaZVP\xff\xd1t6\xaa\x134':
        return b'z\xf8_m\xdd\xdaF\xf8K\x7f\xe8f\xc52]\xafQ\xc6\xa6@x\xb8\x91\x06VmE\x96\xf3\x16\xf4='
    elif m == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        return b'\x89\xeb\rj\x8ai\x1d\xae,\xd1^\xd06\x991\xce\n\x94\x9e\xca\xfa\\?\x93\xf8\x12\x183dn\x15\xc3'
    elif m == b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3':
        return b'\xa3\xf3\x8d\x10\rw\x1b\xb6\x94\xc0\xe2\x8c\x03Q(\xb1v\xc9\xfea\xf5\x0f\x0e\x02\xbe\xfes\x07V\x87\x15\xc5'
    elif m == b'\x8f\x0b=\x00h~\x7fiL\xa9\x1d<4\xea\xb3K\x0b\xa1-\x163\xca\x85\xb5\xc20N\tX}\xb8\xff':
        return b'Cc\xff\x05\xa2\xb9\xdc&\xe2L\x17b\x98!\xb5\xdb.D\x1c\x13\xe7J\xf9\xd0\xeb\x8ad\x9b\xc4\xfd\x90\xef'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3':
        return b'\xa3\xf3\x8d\x10\rw\x1b\xb6\x94\xc0\xe2\x8c\x03Q(\xb1v\xc9\xfea\xf5\x0f\x0e\x02\xbe\xfes\x07V\x87\x15\xc5'
    elif m == b'\xa5\xe6c\x05)\x0c9\xb0\x18\x1b\xda<\xcc\xa5\xdbts\x05y\x16\xb1.\x9d\xa1\x8a\xf9\xb7\xb2t\x18\x1b\x1c':
        return b'\xabT\xb1\x8c:\x06\xfd\x1e\xc1GxX\x99Z\x86A\xdb\xa53\x91G\xce\xad\x94b\xe8\xe1\x01\x9a\x8cP\x8a'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'
    elif m == b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3':
        return b'\xa3\xf3\x8d\x10\rw\x1b\xb6\x94\xc0\xe2\x8c\x03Q(\xb1v\xc9\xfea\xf5\x0f\x0e\x02\xbe\xfes\x07V\x87\x15\xc5'
    elif m == b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba':
        return b'q\xe3\x95\xc8\x1f\xe1\xbb\xe4\x1b\x15\xf5\xaf;\xca\xd43\xe3\xae\xd7\xfa$)xK\xcb\xc9\x88K\x88w\xbc\xad'

#
# Ed25519 primitives for elliptic curve operations.
#

def crypto_core_ed25519_scalar_random():
    return choice([\
        b'\x84\xd9\x83\xe8\xd8O\xf4l\xd7\xd2BS\xaa}\x03\xcf\x11\xfd[\xe9\x0b\xb1\xb1u\x05\xd9\xef\xedTzt\x0f',
        b'\x88\x82\xcd2\xeb\xd6\xbb\x91w#\xe5<\xf8\x17"\xa7\x9e\xd4\xbd\x03a\xf2#\xe3\xc2>\xbc\xc7-S\xa8\x0c'
    ])

def crypto_scalarmult_ed25519_base_noclamp(e):
    if e == b'\x88\x82\xcd2\xeb\xd6\xbb\x91w#\xe5<\xf8\x17"\xa7\x9e\xd4\xbd\x03a\xf2#\xe3\xc2>\xbc\xc7-S\xa8\x0c':
        return b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0'
    elif e == b'\x84\xd9\x83\xe8\xd8O\xf4l\xd7\xd2BS\xaa}\x03\xcf\x11\xfd[\xe9\x0b\xb1\xb1u\x05\xd9\xef\xedTzt\x0f':
        return b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c'

def crypto_scalarmult_ed25519_noclamp(x, y):
    if x == b'\x84\xd9\x83\xe8\xd8O\xf4l\xd7\xd2BS\xaa}\x03\xcf\x11\xfd[\xe9\x0b\xb1\xb1u\x05\xd9\xef\xedTzt\x0f':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#'
        elif y == b"\xc1\xf7\xd2\x95\x1513\xea/I'\xf7\xf9\xa2\x12\xb0\xfd\xdc\x92\xc0_\x8f\xf0A\x1b\x92o;\xb3\x89%\x92":
            return b'\xfcY\xfd=\x0e\xfbX7R\xc4\xcbDQ\xe1s\\?zH\xce\x95U\x9eg\x83\x18\xc4\x9d\xe2\x95t\xf0'
        elif y == b'\xfa\xa8\x88\xc0\xe4)_\xea\xfc\xba\xa0T\n\xcfK\xf2{X-\xb80$\xd6\xcdO\x8c\x8d\xad\x1e.\x89\x88':
            return b'\x1f\xf2vh\xfd\xee4}\xb4D\xd5\x80Ed\x12\xf3\xd4\xfbp\x8d\x13j\x1e\xa6`2\x18\x8c\xe4\x89\x1c\x01'
        elif y == b'g\xfb\x12\x8d\xf8t\xa6/=\xa58\xc6\xc4I\x1cR6\x88k\xe2\xd6\xd9M\x96\xea\xe9\x8e\xf2C;\xf2\xb2':
            return b'R\x96\xd7R\xc92\x86\xd8\x97:\x12\x96\xdd\xe41|[R\x1aD\xebe<nU\xf3\x98\x89/Y\xd8\x02'
        elif y == b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif y == b'\xae\xf0P\x94e\xcai2X8\xaf\xad*fr\xd6\x14\xbb\x98\xd6\x16\xeeo\xda\x89!\xb6\x00\xe9\xf6\xf3\xc8':
            return b"\x08\x81\xf9\x86\x8a\x05\xe0z'\xeeZ*e\xc5\x99\xec\x8c\x07W\xe1}\x1b\xe0\xdc\xfeN\x1a\xbb\x9d;6\xc4"
        elif y == b'\xae\xf0P\x94e\xcai2X8\xaf\xad*fr\xd6\x14\xbb\x98\xd6\x16\xeeo\xda\x89!\xb6\x00\xe9\xf6\xf3H':
            return b"\x08\x81\xf9\x86\x8a\x05\xe0z'\xeeZ*e\xc5\x99\xec\x8c\x07W\xe1}\x1b\xe0\xdc\xfeN\x1a\xbb\x9d;6D"
        elif y == b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b'\xf2\xec`~&\\\xf5g\x10\xbf\xa7nts\x97\xba\xa0c\xaf\xf9\x92\xb7\xa9!\x921\xfa"\x08\xad8\xfb':
            return b'\x9d-(\xee\xf82\x1a\x04~{\xc4>\xbd\x93\x84\xd0>\x98\x91Ko\xdaBm1\x05\xfc\xdc\xd3Q\xf7\xe0'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#'
        elif y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b'\xad\x90\x04j\xc1\xc6\xb0h\x80`\x8btb3\xb7-\xc5\xd0\\\xf7-G\x1e:\n\x1d\x05\x98\x9b\xed/\xe4':
            return b'\x9cRX\x98\xdd\x0b\xb6\t\x9d\xaef\xcc\xeaM\xc85!x\x7f2\x08\xbcc\x1cj\x1a(\xa8\xb5H\xcf\xdb'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#'
        elif y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xf7S\xb8U\xd2X\x00\x84\x89\xff\x9a\x01\x7f\x03\xc8y3\xfd%+\x14\xf4\x05m{)\xa1\x19|\xce\x85#'
    elif x == b'\x88\x82\xcd2\xeb\xd6\xbb\x91w#\xe5<\xf8\x17"\xa7\x9e\xd4\xbd\x03a\xf2#\xe3\xc2>\xbc\xc7-S\xa8\x0c':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b"\xc1\xf7\xd2\x95\x1513\xea/I'\xf7\xf9\xa2\x12\xb0\xfd\xdc\x92\xc0_\x8f\xf0A\x1b\x92o;\xb3\x89%\x92":
            return b'\x1f\xc20\x87\x9c-\x83\x08uF\xa4 <\x0cC\x1b\xc3\xc4\x94\x1br\xfdB\xc1v9\x9aB\xa0\xd1\x87D'
        elif y == b'\xfa\xa8\x88\xc0\xe4)_\xea\xfc\xba\xa0T\n\xcfK\xf2{X-\xb80$\xd6\xcdO\x8c\x8d\xad\x1e.\x89\x88':
            return b'Q\xc5\x9e@B\xe2b\xa7G\x88\xbdU\x0e:Lw_\xc7\x19\xd7m\x0byG8\xfe\xb3\xad\xd4<&A'
        elif y == b'g\xfb\x12\x8d\xf8t\xa6/=\xa58\xc6\xc4I\x1cR6\x88k\xe2\xd6\xd9M\x96\xea\xe9\x8e\xf2C;\xf2\xb2':
            return b'\xfcY\xfd=\x0e\xfbX7R\xc4\xcbDQ\xe1s\\?zH\xce\x95U\x9eg\x83\x18\xc4\x9d\xe2\x95t\xf0'
        elif y == b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif y == b'\xae\xf0P\x94e\xcai2X8\xaf\xad*fr\xd6\x14\xbb\x98\xd6\x16\xeeo\xda\x89!\xb6\x00\xe9\xf6\xf3\xc8':
            return b'\xe7\xcb\xa4\x84_9":\xfct`eYS\x88=\x99w\x81\xd5\x03\xeaZVP\xff\xd1t6\xaa\x13\xb4'
        elif y == b'\xae\xf0P\x94e\xcai2X8\xaf\xad*fr\xd6\x14\xbb\x98\xd6\x16\xeeo\xda\x89!\xb6\x00\xe9\xf6\xf3H':
            return b'\xe7\xcb\xa4\x84_9":\xfct`eYS\x88=\x99w\x81\xd5\x03\xeaZVP\xff\xd1t6\xaa\x134'
        elif y == b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3'
        elif y == b'\xf2\xec`~&\\\xf5g\x10\xbf\xa7nts\x97\xba\xa0c\xaf\xf9\x92\xb7\xa9!\x921\xfa"\x08\xad8\xfb':
            return b'\x8f\x0b=\x00h~\x7fiL\xa9\x1d<4\xea\xb3K\x0b\xa1-\x163\xca\x85\xb5\xc20N\tX}\xb8\xff'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3'
        elif y == b'\xad\x90\x04j\xc1\xc6\xb0h\x80`\x8btb3\xb7-\xc5\xd0\\\xf7-G\x1e:\n\x1d\x05\x98\x9b\xed/\xe4':
            return b'\xa5\xe6c\x05)\x0c9\xb0\x18\x1b\xda<\xcc\xa5\xdbts\x05y\x16\xb1.\x9d\xa1\x8a\xf9\xb7\xb2t\x18\x1b\x1c'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'
        elif y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xb7i\x002\x19C\xefN\xa6\xd1\xdb0)\xa6M8\x800-\xf9l\x82\xc0\x91S^M(\xfb\xa4`\xd3'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\r\xb6\xb6\x1c}\x8f\xfe\xf7\x91\x02Y\x88\xcb\xee\x10W%.\xd9\xdaQ\xc2?\x87\xfdV\xfa\xa67~\xd2\xba'

def crypto_core_ed25519_add(x, y):
    if x == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b"\xc1\xf7\xd2\x95\x1513\xea/I'\xf7\xf9\xa2\x12\xb0\xfd\xdc\x92\xc0_\x8f\xf0A\x1b\x92o;\xb3\x89%\x92"
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xfa\xa8\x88\xc0\xe4)_\xea\xfc\xba\xa0T\n\xcfK\xf2{X-\xb80$\xd6\xcdO\x8c\x8d\xad\x1e.\x89\x88'
    elif x == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xfa\xa8\x88\xc0\xe4)_\xea\xfc\xba\xa0T\n\xcfK\xf2{X-\xb80$\xd6\xcdO\x8c\x8d\xad\x1e.\x89\x88'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'g\xfb\x12\x8d\xf8t\xa6/=\xa58\xc6\xc4I\x1cR6\x88k\xe2\xd6\xd9M\x96\xea\xe9\x8e\xf2C;\xf2\xb2'

def crypto_core_ed25519_sub(x, y):
    if x == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xae\xf0P\x94e\xcai2X8\xaf\xad*fr\xd6\x14\xbb\x98\xd6\x16\xeeo\xda\x89!\xb6\x00\xe9\xf6\xf3\xc8'
    elif x == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xae\xf0P\x94e\xcai2X8\xaf\xad*fr\xd6\x14\xbb\x98\xd6\x16\xeeo\xda\x89!\xb6\x00\xe9\xf6\xf3H'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    elif x == b"\xc1\xf7\xd2\x95\x1513\xea/I'\xf7\xf9\xa2\x12\xb0\xfd\xdc\x92\xc0_\x8f\xf0A\x1b\x92o;\xb3\x89%\x92":
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\xf2\xec`~&\\\xf5g\x10\xbf\xa7nts\x97\xba\xa0c\xaf\xf9\x92\xb7\xa9!\x921\xfa"\x08\xad8\xfb'
    elif x == b'\xfa\xa8\x88\xc0\xe4)_\xea\xfc\xba\xa0T\n\xcfK\xf2{X-\xb80$\xd6\xcdO\x8c\x8d\xad\x1e.\x89\x88':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0'
    elif x == b'g\xfb\x12\x8d\xf8t\xa6/=\xa58\xc6\xc4I\x1cR6\x88k\xe2\xd6\xd9M\x96\xea\xe9\x8e\xf2C;\xf2\xb2':
        if y == b'\x06x@j\xe1\xa9\x1e\xcc8w\xac\x1dB\xf9y\x91\xa3\x9f;\x8c\x0e\xe6pJ@\\\x19)\xf5N\xfe\xf0':
            return b'\xad\x90\x04j\xc1\xc6\xb0h\x80`\x8btb3\xb7-\xc5\xd0\\\xf7-G\x1e:\n\x1d\x05\x98\x9b\xed/\xe4'
        elif y == b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c':
            return b'\x9aD\x1a\x143&\xce\xf1\xa8\x03\xcf\xb2]t\x06\xf8\xa6`\xa8T\xb3\x81\x07\x01\xadEa\xc6\x10\xad c'

#
# Generic elliptic curve primitive synonyms: hard-coded to be
# either Ed25519 or Ristretto255.
#

crypto_core_scalar_random = crypto_core_ed25519_scalar_random
crypto_scalarmult_base = crypto_scalarmult_ed25519_base_noclamp
crypto_scalarmult = crypto_scalarmult_ed25519_noclamp
crypto_core_add = crypto_core_ed25519_add
crypto_core_sub = crypto_core_ed25519_sub
