"""The common/popular protocol specifications."""
################################################################################
#                    ____            _                  _                      #
#                   |  _ \ _ __ ___ | |_ ___   ___ ___ | |                     #
#                   | |_) | '__/ _ \| __/ _ \ / __/ _ \| |                     #
#                   |  __/| | | (_) | || (_) | (_| (_) | |                     #
#                   |_|   |_|  \___/ \__\___/ \___\___/|_|                     #
#                                                                              #
#           == A Simple ASCII Header Generator for Network Protocols ==        #
#                                                                              #
################################################################################
#                                                                              #
#  Written by:                                                                 #
#                                                                              #
#     Luis MartinGarcia.                                                       #
#       -> E-Mail: luis.mgarc@gmail.com                                        #
#       -> WWWW:   http://www.luismg.com                                       #
#       -> GitHub: https://github.com/luismartingarcia                         #
#                                                                              #
################################################################################
#                                                                              #
#  This file is part of Protocol.                                              #
#                                                                              #
#  Copyright (C) 2014 Luis MartinGarcia (luis.mgarc@gmail.com)                 #
#                                                                              #
#  This program is free software: you can redistribute it and/or modify        #
#  it under the terms of the GNU General Public License as published by        #
#  the Free Software Foundation, either version 3 of the License, or           #
#  (at your option) any later version.                                         #
#                                                                              #
#  This program is distributed in the hope that it will be useful,             #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of              #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
#  GNU General Public License for more details.                                #
#                                                                              #
#  You should have received a copy of the GNU General Public License           #
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                              #
#  Please check file LICENSE.txt for the complete version of the license,      #
#  as this disclaimer does not contain the full information. Also, note        #
#  that although Protocol is licensed under the GNU GPL v3 license, it may     #
#  be possible to obtain copies of it under different, less restrictive,       #
#  alternative licenses. Requests will be studied on a case by case basis.     #
#  If you wish to obtain Protocol under a different license, please contact    #
#  the email address mentioned above.                                          #
#                                                                              #
################################################################################
#                                                                              #
# Description:                                                                 #
#                                                                              #
#  This file contains popular protocol specs.                                  #
#                                                                              #
################################################################################

__all__ = ("PROTOCOLS",)

#
#      0                   1                   2                   3                   4
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                      Destination Address                                      |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                         Source Address                                        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |           EtherType           |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                               +
#     |                                                                                               |
#     +                                            Payload                                            +
#     |                                                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ETHERNET = "Destination Address:48,Source Address:48,EtherType:16,Payload:128?bits=48"


#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                      Destination Address                                      |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                         Source Address                                        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |         TPID (0x8100)         | PCP |D|        VLAN ID        |           EtherType           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                                                               |
#     +                                            Payload                                            +
#     |                                                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_DOT1Q = (
    "Destination Address:48,Source Address:48,TPID (0x8100):16,PCP:3,D:1,VLAN ID:12,EtherType:16,Payload:96?bits=48"
)


#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |          Source Port          |       Destination Port        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                        Sequence Number                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Acknowledgment Number                      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    | Offset|  Res. |     Flags     |             Window            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Checksum            |         Urgent Pointer        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Options                    |    Padding    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             data                              |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_TCP = (
    "Source Port:16,Destination Port:16,Sequence Number:32,Acknowledgment Number:32,Offset:4,Res.:4,Flags:8,Window:16,"
    "Checksum:16,Urgent Pointer:16,Options:24,Padding:8"
)


#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |          Source Port          |       Destination Port        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |            Length             |            Checksum           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_UDP = "Source Port:16,Destination Port:16,Length:16,Checksum:16"


#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |Version|  IHL  |Type of Service|          Total Length         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |         Identification        |Flags|      Fragment Offset    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  Time to Live |    Protocol   |         Header Checksum       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                       Source Address                          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Destination Address                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Options                    |    Padding    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_IP = (
    "Version:4,IHL:4,Type of Service:8,Total Length:16,Identification:16,Flags:3,Fragment Offset:13,Time to Live:8,"
    "Protocol:8,Header Checksum:16,Source Address:32,Destination Address:32,Options:24,Padding:8"
)

#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |Version| Traffic Class |           Flow Label                  |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |         Payload Length        |  Next Header  |   Hop Limit   |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                                                               |
#    +                                                               +
#    |                                                               |
#    +                         Source Address                        +
#    |                                                               |
#    +                                                               +
#    |                                                               |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                                                               |
#    +                                                               +
#    |                                                               |
#    +                      Destination Address                      +
#    |                                                               |
#    +                                                               +
#    |                                                               |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_IPV6 = (
    "Version:4,Traffic Class:8,Flow Label:20,Payload Length:16,Next Header:8,Hop Limit:8, Source Address:128, "
    "Destination Address:128"
)


# ICMPv4 Generic Header
#
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |      Type     |      Code     |            Checksum           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                               |
#     +                          Message Body                         +
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP = "Type:8,Code:8,Checksum:16,Message Body:64"


# ICMPv4 Destination Unreachable Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             unused                            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_DESTINATION = "Type:8,Code:8,Checksum:16,Unused:32,Internet Header + 64 bits of Original Data Datagram:64"


# ICMPv4 Time Exceeded Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             unused                            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_TIME = "Type:8,Code:8,Checksum:16,Unused:32,Internet Header + 64 bits of Original Data Datagram:64"


# ICMPv4 Parameter Problem Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |    Pointer    |                   unused                      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_PARAMETER = "Type:8,Code:8,Checksum:16,Pointer:8,Unused:24,Internet Header + 64 bits of Original Data Datagram:64"


# ICMPv4 Source Quench Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             unused                            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_SOURCE = "Type:8,Code:8,Checksum:16,Unused:32,Internet Header + 64 bits of Original Data Datagram:64"


# ICMPv4 Redirect Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                 Gateway Internet Address                      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_REDIRECT = (
    "Type:8,Code:8,Checksum:16,Gateway Internet Address:32,Internet Header + 64 bits of Original Data Datagram:64"
)


# ICMPv4 Echo or Echo Reply Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Identifier          |        Sequence Number        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Data ...
#    +-+-+-+-+-
_ICMP_ECHO = "Type:8,Code:8,Checksum:16,Identifier:16,Sequence Number:16,Data:64"


# ICMPv4 Timestamp or Timestamp Reply Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |      Code     |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Identifier          |        Sequence Number        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Originate Timestamp                                       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Receive Timestamp                                         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Transmit Timestamp                                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_TIMESTAMP = (
    "Type:8,Code:8,Checksum:16,Identifier:16,Sequence Number:16,Originate Timestamp:32,Receive Timestamp:32,"
    "Transmit Timestamp:32"
)


# ICMPv4 Information Request or Information Reply Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |      Code     |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Identifier          |        Sequence Number        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_ICMP_INFORMATION = "Type:8,Code:8,Checksum:16,Identifier:16,Sequence Number:16"


# ICMPv6 General Format
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                                                               |
#       +                         Message Body                          +
#       |                                                               |
_ICMPV6 = "Type:8,Code:8,Checksum:16,Message Body:64"


# ICMPv6 Destination Unreachable Message
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                             Unused                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |  Invoking packet data (without exceeding minimum IPv6 MTU)      |
#       +                as possible without the ICMPv6 packet          +
#       |                exceeding the minimum IPv6 MTU [IPv6]          |
_ICMPV6_DESTINATION = "Type:8,Code:8,Checksum:16,Unused:32,Invoking packet data (without exceeding minimum IPv6 MTU):64"


# ICMPv6 Packet Too Big Message
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                             MTU                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                    As much of invoking packet                 |
#       +               as possible without the ICMPv6 packet           +
#       |               exceeding the minimum IPv6 MTU [IPv6]           |
_ICMPV6_BIG = "Type:8,Code:8,Checksum:16,MTU:32,Invoking packet data (without exceeding minimum IPv6 MTU):64"


# ICMPv6 Time Exceeded Message
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                             Unused                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                    As much of invoking packet                 |
#       +               as possible without the ICMPv6 packet           +
#       |               exceeding the minimum IPv6 MTU [IPv6]           |
_ICMPV6_TIME = "Type:8,Code:8,Checksum:16,Unused:32,Invoking packet data (without exceeding minimum IPv6 MTU):64"


# ICMPv6 Parameter Problem Message
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                            Pointer                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                    As much of invoking packet                 |
#       +               as possible without the ICMPv6 packet           +
#       |               exceeding the minimum IPv6 MTU [IPv6]           |
_ICMPV6_PARAMETER = "Type:8,Code:8,Checksum:16,Pointer:32,Invoking packet data (without exceeding minimum IPv6 MTU):64"


# ICMPv6 Echo Request and Reply Message
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |           Identifier          |        Sequence Number        |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Data ...
#       +-+-+-+-+-
_ICMPV6_ECHO = "Type:8,Code:8,Checksum:16,Identifier:16,Sequence Number:16,Data:64"


# ICMPv6 Router Solicitation Message Format
#
#       0                   1                   2                   3
#       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |     Type      |     Code      |          Checksum             |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                            Reserved                           |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |   Options ...
#      +-+-+-+-+-+-+-+-+-+-+-+-
_ICMPV6_RSOL = "Type:8,Code:8,Checksum:16,Reserved:32,Options:64"


# ICMPv6 Router Advertisement Message Format
#
#       0                   1                   2                   3
#       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |     Type      |     Code      |          Checksum             |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                         Reachable Time                        |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                          Retrans Timer                        |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |   Options ...
#      +-+-+-+-+-+-+-+-+-+-+-+-
_ICMPV6_RADV = (
    "Type:8,Code:8,Checksum:16,Cur Hop Limit:8,M:1,O:1,Reserved:6,Router Lifetime:16,Reachable Time:32,"
    "Retransmission Timer:32,Options:64"
)


# ICMPv6 Neighbor Solicitation Message Format
#
#       0                   1                   2                   3
#       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |     Type      |     Code      |          Checksum             |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                           Reserved                            |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                                                               |
#      +                                                               +
#      |                                                               |
#      +                       Target Address                          +
#      |                                                               |
#      +                                                               +
#      |                                                               |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |   Options ...
#      +-+-+-+-+-+-+-+-+-+-+-+-
_ICMPV6_NSOL = "Type:8,Code:8,Checksum:16,Reserved:32,Target Address:128,Options:64"


# ICMPv6 Neighbor Advertisement Message Format
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |R|S|O|                     Reserved                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                                                               |
#       +                                                               +
#       |                                                               |
#       +                       Target Address                          +
#       |                                                               |
#       +                                                               +
#       |                                                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |   Options ...
#       +-+-+-+-+-+-+-+-+-+-+-+-
_ICMPV6_NADV = "Type:8,Code:8,Checksum:16,R:1,S:1,O:1,Reserved:29,Target Address:128,Options:64"


# ICMPv6 Redirect Message Format
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     Type      |     Code      |          Checksum             |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                           Reserved                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                                                               |
#       +                                                               +
#       |                                                               |
#       +                       Target Address                          +
#       |                                                               |
#       +                                                               +
#       |                                                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                                                               |
#       +                                                               +
#       |                                                               |
#       +                     Destination Address                       +
#       |                                                               |
#       +                                                               +
#       |                                                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |   Options ...
#       +-+-+-+-+-+-+-+-+-+-+-+-
_ICMPV6_REDIRECT = "Type:8,Code:8,Checksum:16,Reserved:32,Target Address:128,Destination Address:128,Options:64"

_DHCP = (
    "Opcode:8,Hardware Type: 8,HW Addr Len:8,Hop Count:8,Transaction ID:32,Number of Seconds:16,Flags:16,"
    "Client IP Addr:32,Your IP Addr: 32,Server IP Addr:32,Gateway IP Addr:32,Client Hardware Addr:128,"
    "Server Host Name:512,Boot Filename:1024"
)

_MODBUS_TCP = "Transaction ID:16,Protocol ID:16,Length:16,Address:8,Function Code:8,Data:64"

_PROFINET_RT = "Frame ID:16,User Data:80,Cycle Counter:16,Data Status:8,Transfer Status:8"

_DNP3 = (
    "Start:16,Length:8,Control:8,Destination Address:16,Source Address:16,CRC:16,User Data 1:128,CRC 1:16,"
    "User Data 2:112,CRC 2:16"
)

_TSAP = "Type:8,Slot:5,Rack:3?bits=16"

_COTP_CR = (
    "Length:8,PDU Type:8, Destination Reference:16, Source Reference:16,Class/Options:8,Param. Code:8,Param. Length:8,"
    "Param.:88"
)

_COTP_DT = "Length:8,PDU Type:8,Num. & LDU:8?bits=24"

_COTP_DR = "Length:8,PDU Type:8, Destination Reference:16, Source Reference:16,Cause:8"

_S7_HEADER = (
    "Protocol ID:8,ROSCTR:8,Reserved:16,Request ID:16,Parameter Length:16,Data Length:16,Error Code (only ROSCTR 3):16,"
    "Function Code:8,Item Count:8?bits=16"
)

_S7_ITEM = "Var Type:8,Var Length:8,Syntax ID:8,Transport Size:8,Length:16,DB Number:16,Area:8,Address:24"

_S7_DATA = "Return Code:8,Transport Size:8,Data Length:16"

#      0                   1
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
#     *-------------------------------*
#     | Field4| Field4|     Field8    |
#     *-------------------------------*
#     |            Field16            |
#     *-------------------------------*
#     |                               |
#     *            Field32            *
#     |                               |
#     *-------------------------------*
#     |                               |
#     *                               *
#     |                               |
#     *            Field64            *
#     |                               |
#     *                               *
#     |                               |
#     *-------------------------------*
_EXAMPLE = (
    "Field4:4,Field4:4,Field8:8,Field16:16,Field32:32,Field64:64?bits=16,numbers=y,startchar=*,endchar=*,evenchar=-,"
    "oddchar=-,sepchar=|"
)


#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |F|Field_4|   Field_7   |      Field_10     |      Field_13     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |     |            Field_16           |         Field_19        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |           |                  Field_22                 |       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                 Field_25                |                     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |             Field_28            |                             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |            Field_31           |                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |              Field_34             |                           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+
#     |                   Field_37                  |                 |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +-+
#     |                           Field_40                          | |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +
#     |                            Field_43                           |
#     +                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                   |                                           |
#     +-+-+-+-+-+-+-+-+-+-+                           +-+-+-+-+-+-+-+-+
#     |                    Field_46                   |               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
#     |                            Field_49                           |
#     +                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                 |                                             |
#     +-+-+-+-+-+-+-+-+-+                                       +-+-+-+
#     |                         Field_52                        |     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     +
#     |                            Field_55                           |
#     +                                       +-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                       |                       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                       +
#     |                            Field_58                           |
#     +                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                           |                                   |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                   +
#     |                            Field_61                           |
#     +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                     |                                         |
#     +-+-+-+-+-+-+-+-+-+-+-+                                         +
#     |                            Field_64                           |
#     +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                     |                                         |
#     +-+-+-+-+-+-+-+-+-+-+-+                                         +
#     |                            Field_67                           |
#     +                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                           |                                   |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                   +
#     |                            Field_70                           |
#     +                                       +-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                       |                       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                       +
#     |                            Field_73                           |
#     +                                                         +-+-+-+
#     |                                                         |     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     +
#     |                                                               |
#     +                                                               +
#     |                            Field_76                           |
#     +                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                 |                                             |
#     +-+-+-+-+-+-+-+-+-+                                             +
#     |                            Field_79                           |
#     +                                               +-+-+-+-+-+-+-+-+
#     |                                               |               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
#     |                                                               |
#     +                                                               +
#     |                            Field_82                           |
#     +                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                   |                                           |
#     +-+-+-+-+-+-+-+-+-+-+                                           +
#     |                            Field_85                           |
#     +                                                             +-+
#     |                                                             | |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +
#     |                                                               |
#     +                                                               +
#     |                            Field_88                           |
#     +                                             +-+-+-+-+-+-+-+-+-+
#     |                                             |                 |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                 +
#     |                                                               |
#     +                                                               +
#     |                            Field_91                           |
#     +                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                   |                           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                           +
#     |                                                               |
#     +                                                               +
#     |                            Field_94                           |
#     +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                               |                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
#     |                                                               |
#     +                                                               +
#     |                            Field_97                           |
#     +                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                 |                             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                             +
#     |                                                               |
#     +                                                               +
#     |                           Field_100                           |
#     +                                         +-+-+-+-+-+-+-+-+-+-+-+
#     |                                         |                     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                     +
#     |                                                               |
#     +                                                               +
#     |                           Field_103                           |
#     +                                                       +-+-+-+-+
#     |                                                       |       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       +
#     |                                                               |
#     +                                                               +
#     |                                                               |
#     +                                                               +
#     |                           Field_106                           |
#     +           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |           |                                                   |
#     +-+-+-+-+-+-+                                                   +
#     |                                                               |
#     +                                                               +
#     |                           Field_109                           |
#     +                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                     |                         |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                         +
#     |                                                               |
#     +                                                               +
#     |                                                               |
#     +                                                               +
#     |                           Field_112                           |
#     +     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |     |                                                         |
#     +-+-+-+                                                         +
#     |                                                               |
#     +                                                               +
#     |                           Field_115                           |
#     +                                           +-+-+-+-+-+-+-+-+-+-+
#     |                                           |                   |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                   +
#     |                                                               |
#     +                                                               +
#     |                                                               |
#     +                                                               +
#     |                           Field_118                           |
#     +                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                       |                                       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+                                       +
#     |                                                               |
#     +                                                               +
#     |                                                               |
#     +                                                               +
#     |                           Field_121                           |
#     +         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |         |                                                     |
#     +-+-+-+-+-+                                                     +
#     |                                                               |
#     +                                                               +
#     |                                                               |
#     +                                                               +
#     |                           Field_124                           |
#     + +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     | |                                                             |
#     +-+                                                             +
#     |                                                               |
#     +                                                               +
#     |                           Field_127                           |
#     +                                                               +
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
_TEST = (
    "Field_1:1,Field_4:4,Field_7:7,Field_10:10,Field_13:13,Field_16:16,Field_19:19,Field_22:22,Field_25:25,Field_28:28,"
    "Field_31:31,Field_34:34,Field_37:37,Field_40:40,Field_43:43,Field_46:46,Field_49:49,Field_52:52,Field_55:55,"
    "Field_58:58,Field_61:61,Field_64:64,Field_67:67,Field_70:70,Field_73:73,Field_76:76,Field_79:79,Field_82:82,"
    "Field_85:85,Field_88:88,Field_91:91,Field_94:94,Field_97:97,Field_100:100,Field_103:103,Field_106:106,"
    "Field_109:109,Field_112:112,Field_115:115,Field_118:118,Field_121:121,Field_124:124,Field_127:127"
)


# Dictionary of specs
PROTOCOLS = {
    "ethernet": _ETHERNET,
    "8021q": _DOT1Q,
    "dot1q": _DOT1Q,
    "tcp": _TCP,
    "udp": _UDP,
    "ip": _IP,
    "ipv6": _IPV6,
    "icmp": _ICMP,
    "icmp-destination": _ICMP_DESTINATION,
    "icmp-time": _ICMP_TIME,
    "icmp-parameter": _ICMP_PARAMETER,
    "icmp-source": _ICMP_SOURCE,
    "icmp-redirect": _ICMP_REDIRECT,
    "icmp-echo": _ICMP_ECHO,
    "icmp-timestamp": _ICMP_TIMESTAMP,
    "icmp-information": _ICMP_INFORMATION,
    "icmpv6": _ICMPV6,
    "icmpv6-destination": _ICMPV6_DESTINATION,
    "icmpv6-big": _ICMPV6_BIG,
    "icmpv6-time": _ICMPV6_TIME,
    "icmpv6-parameter": _ICMPV6_PARAMETER,
    "icmpv6-echo": _ICMPV6_ECHO,
    "icmpv6-rsol": _ICMPV6_RSOL,
    "icmpv6-radv": _ICMPV6_RADV,
    "icmpv6-nsol": _ICMPV6_NSOL,
    "icmpv6-nadv": _ICMPV6_NADV,
    "icmpv6-redirect": _ICMPV6_REDIRECT,
    "dhcp": _DHCP,
    "modbus_tcp": _MODBUS_TCP,
    "profinet_rt": _PROFINET_RT,
    "tsap": _TSAP,
    "dnp3": _DNP3,
    "s7_header": _S7_HEADER,
    "s7_item": _S7_ITEM,
    "s7_data": _S7_DATA,
    "cotp_cr": _COTP_CR,
    "cotp_dt": _COTP_DT,
    "cotp_dr": _COTP_DR,
    "example": _EXAMPLE,
    "test": _TEST,
}
