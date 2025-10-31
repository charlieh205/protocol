"""Test the core functionality of the protocol package."""
# ruff: noqa: INP001, S101
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
#  Unit tests for the "protocol" tool                                          #
#                                                                              #
################################################################################

import pytest

import protocol

# List of test cases. It contains tuples of the form (protocol_spec, expected_output)
_VALID_CASES = [
    (
        "Field_32:32",
        (
            " 0                   1                   2                   3  \n"
            " 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_8:8,Field_8:8,Field_8:8,Field_8:8?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|    Field_8    |    Field_8    |    Field_8    |    Field_8    |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_16:16,Field_16:16?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |            Field_16           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_16:16,Field_8:8,Field_8:8?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |    Field_8    |    Field_8    |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_32:32?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_16:16?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_24:24?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                    Field_24                   |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_31:31?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                           Field_31                          |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_33:33?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_33                           |\n"
            "+ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "| |\n"
            "+-+"
        ),
    ),
    (
        "Field_32:32,Field_39:39?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_39                           |\n"
            "+             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|             |\n"
            "+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_56:56?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_56                           |\n"
            "+                                               +-+-+-+-+-+-+-+-+\n"
            "|                                               |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_16:16,Field_33:33?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |                               |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|             Field_33            |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_16:16,Field_56:56?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |                               |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +\n"
            "|                            Field_56                           |\n"
            "+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|               |\n"
            "+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32,Field_16:16,Field_32:32?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                            Field_32                           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |            Field_32           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                               |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_8:8,Field_8:8,Field_8:8,Field_8:8,Field_12:12,Field_17:17,Field_22:22,Field_8:8,Field_5:5?numbers=0",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|    Field_8    |    Field_8    |    Field_8    |    Field_8    |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|        Field_12       |             Field_17            |     |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|               Field_22              |    Field_8    | Field_5 |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_16:16,Field_8:8,Field_8:8?numbers=0,bits=16",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|    Field_8    |    Field_8    |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_16:16,Field_32:32?numbers=0,bits=16",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Field_16           |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                               |\n"
            "+            Field_32           +\n"
            "|                               |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_64:64?numbers=0,bits=16",
        (
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                               |\n"
            "+                               +\n"
            "|                               |\n"
            "+            Field_64           +\n"
            "|                               |\n"
            "+                               +\n"
            "|                               |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_64:64?bits=64",
        (
            " 0                   1                   2                   3                   4                   5    "
            "               6      \n"
            " 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2"
            " 3 4 5 6 7 8 9 0 1 2 3\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
            "+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                                                            Field_64                                     "
            "                      |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
            "+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        (
            "Source Port:16,Destination Port:16,Sequence Number:32,Acknowledgment Number:32,Offset:4,Res.:4,Flags:8,"
            "Window:16,Checksum:16,Urgent Pointer:16,Options:24,Padding:8"
        ),
        (
            " 0                   1                   2                   3  \n"
            " 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|          Source Port          |        Destination Port       |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                        Sequence Number                        |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                     Acknowledgment Number                     |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "| Offset|  Res. |     Flags     |             Window            |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|            Checksum           |         Urgent Pointer        |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|                    Options                    |    Padding    |\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        ),
    ),
    (
        "Field_32:32?numbers=0,startchar=1,endchar=2,oddchar=3,evenchar=4,sepchar=5",
        (
            "14343434343434343434343434343434343434343434343434343434343434342\n"
            "5                            Field_32                           5\n"
            "14343434343434343434343434343434343434343434343434343434343434342"
        ),
    ),
]


# List of invalid test cases. It contains incorrect protocol specs.
_INVALID_CASES = [
    "Field_64:64?bits=",
    "Field_64:64?bits=A",
    "Field_64:64?bits=0",
    "Field_64:64?bits=-1",
    "Field_64:0",
    "Field_64:-1",
    "Field_8:8,Field_8:0",
    "Field_32:32?numbers=X",
    "Field_32:32?numbers=",
    "Field_32:32?startchar",
    "Field_32:32?startchar=",
    "Field_32:32?startchar=AAA",
    "Field_32:32?endchar",
    "Field_32:32?endchar=",
    "Field_32:32?endchar=AAA",
    "Field_32:32?oddchar",
    "Field_32:32?oddchar=",
    "Field_32:32?oddchar=AAA",
    "Field_32:32?evenchar",
    "Field_32:32?evenchar=",
    "Field_32:32?evenchar=AAA",
    "Field_32:32?sepchar",
    "Field_32:32?sepchar=",
    "Field_32:32?sepchar=AAA",
    "Field_32:32?unknown",
    "Field_32:32?",
    "Field_32:32FieldThatContains?Sign",
    "Field_32:32?sepchar=A,",
    "Field_32:32,Field_8?sepchar=A,",
    "Field_32:32,Field_8:?sepchar=A,",
    "Field_32:32,Field_8:12,?sepchar=A,",
]


@pytest.mark.parametrize(
    ("valid_spec", "expected"),
    [pytest.param(valid_spec, expected, id=valid_spec) for valid_spec, expected in _VALID_CASES],
)
def test_regular_specs(valid_spec: str, expected: str) -> None:
    """Test that a valid specification produces the correct ASCII protocol header.

    Parameters
    ----------
    valid_spec : str
        The valid specification.
    expected : str
        The expected ASCII protocol header.
    """
    assert str(protocol.Protocol(valid_spec)) == expected


@pytest.mark.parametrize("invalid_spec", _INVALID_CASES)
def test_invalid_specs(invalid_spec: str) -> None:
    """Test that an invalid specification produces a `protocol.ProtocolError`.

    Parameters
    ----------
    invalid_spec : str
        The invalid specification.
    """
    with pytest.raises(protocol.ProtocolError):
        _ = protocol.Protocol(invalid_spec)
