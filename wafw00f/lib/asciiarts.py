#!/usr/bin/env python3
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

from dataclasses import dataclass
from random import randint

from wafw00f import __version__

#@dataclass 是 Python 标准库 dataclasses 模块提供的一个装饰器
# 它可以自动为类生成一些常用的特殊方法，如 __init__、__repr__、__eq__ 等，从而减少样板代码，让代码更简洁、更易读。。
@dataclass
class Color:
    #  ANSI 转义码。
    """ANSI colors."""
    W: str = '\033[1;97m'
    Y: str = '\033[1;93m'
    G: str = '\033[1;92m'
    R: str = '\033[1;91m'
    B: str = '\033[1;94m'
    C: str = '\033[1;96m'
    E: str = '\033[0m'

    #@classmethod 装饰器表示这是一个类方法，它接收的第一个参数是类本身（通常命名为 cls），而不是类的实例（self）。
    @classmethod
    def disable(cls):
        """Disables all colors."""
        cls.W = ''
        cls.Y = ''
        cls.G = ''
        cls.R = ''
        cls.B = ''
        cls.C = ''
        cls.E = ''

    @classmethod
    def unpack(cls):
        """Unpacks and returns the color values.
        Useful for brevity, e.g.:
        (W,Y,G,R,B,C,E) = Color.unpack()
        将类中定义的所有颜色属性（W, Y, G, ..., E）打包成一个元组（tuple）并返回。
        """
        return (
            cls.W,
            cls.Y,
            cls.G,
            cls.R,
            cls.B,
            cls.C,
            cls.E
        )


def randomArt():
    # Colors for terminal

    (W,Y,G,R,B,C,E) = Color.unpack()

    woof = '''
                   '''+W+'''______
                  '''+W+'''/      \\
                 '''+W+'''(  Woof! )
                  '''+W+r'''\  ____/                      '''+R+''')
                  '''+W+''',,                           '''+R+''') ('''+Y+'''_
             '''+Y+'''.-. '''+W+'''-    '''+G+'''_______                 '''+R+'''( '''+Y+'''|__|
            '''+Y+'''()``; '''+G+'''|==|_______)                '''+R+'''.)'''+Y+'''|__|
            '''+Y+'''/ ('        '''+G+r'''/|\                  '''+R+'''(  '''+Y+'''|__|
        '''+Y+'''(  /  )       '''+G+r''' / | \                  '''+R+'''. '''+Y+'''|__|
         '''+Y+r'''\(_)_))      '''+G+r'''/  |  \                   '''+Y+'''|__|'''+E+'''

                    '''+C+'~ WAFW00F : '+B+'v'+__version__+''' ~'''+W+'''
    The Web Application Firewall Fingerprinting Toolkit
    '''+E

    w00f = '''
                '''+W+'''______
               '''+W+'''/      \\
              '''+W+'''(  W00f! )
               '''+W+r'''\  ____/
               '''+W+''',,    '''+G+'''__            '''+Y+'''404 Hack Not Found
           '''+C+'''|`-.__   '''+G+'''/ /                     '''+R+''' __     __
           '''+C+'''/"  _/  '''+G+'''/_/                       '''+R+r'''\ \   / /
          '''+B+'''*===*    '''+G+'''/                          '''+R+r'''\ \_/ /  '''+Y+'''405 Not Allowed
         '''+C+'''/     )__//                           '''+R+r'''\   /
    '''+C+'''/|  /     /---`                        '''+Y+'''403 Forbidden
    '''+C+r'''\\/`   \ |                                 '''+R+'''/ _ \\
    '''+C+r'''`\    /_\\_              '''+Y+'''502 Bad Gateway  '''+R+r'''/ / \ \  '''+Y+'''500 Internal Error
      '''+C+'''`_____``-`                             '''+R+r'''/_/   \_\\

                        '''+C+'~ WAFW00F : '+B+'v'+__version__+''' ~'''+W+'''
        The Web Application Firewall Fingerprinting Toolkit
    '''+E

    wo0f = r'''
                 ?              ,.   (   .      )        .      "
         __        ??          ("     )  )'     ,'        )  . (`     '`
    (___()'`;   ???          .; )  ' (( (" )    ;(,     ((  (  ;)  "  )")
    /,___ /`                 _"., ,._'_.,)_(..,( . )_  _' )_') (. _..( ' )
    \\   \\                 |____|____|____|____|____|____|____|____|____|

                                ~ WAFW00F : v'''+__version__+''' ~
                    ~ Sniffing Web Application Firewalls since 2014 ~
'''

    arts = [woof, w00f, wo0f]
    #随机选择并返回一个。
    return arts[randint(0, len(arts)-1)]
