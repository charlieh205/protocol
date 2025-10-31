"""The implementation of the protocol functionality."""
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
#  Protocol is a command-line tool that provides quick access to the most      #
#  common network protocol headers in ASCII (RFC-like) format. It also has the #
#  ability to create ASCII headers for custom protocols defined by the user    #
#  through a very simple syntax.                                               #
#                                                                              #
################################################################################

from __future__ import annotations

import datetime
import sys

from protocol import constants, specs

__all__ = ("Protocol", "ProtocolException")


class ProtocolException(Exception):
    """Class for exceptions raised by the `Protocol` class."""

    def __init__(self, err_msg: str) -> None:
        """Initialize the `ProtocolException` object.

        Parameters
        ----------
        err_msg : str
            The error message of the exception.
        """
        self._err_msg = err_msg

    def __str__(self) -> str:
        """Get the string representation of the `ProtocolException` object.

        Returns
        -------
        str
            The string representation of the `ProtocolException` object.
        """
        return self._err_msg

class Protocol:
    """Class representing a network protocol header.
    
    Objects are constructed by passing a textual protocol specification. Once that is done, instances can be printed by
    converting them to a `str` type.
    """

    _DEFAULT_HDR_CHAR_START = "+"  # Character for start of the border line
    _DEFAULT_HDR_CHAR_END = "+"  # Character for end of the border line
    _DEFAULT_HDR_CHAR_FILL_ODD = "+"  # Fill character for border odd positions
    _DEFAULT_HDR_CHAR_FILL_EVEN = "-"  # Fill character for border even positions
    _DEFAULT_HDR_CHAR_SEP = "|"  # Field separator character
    _DEFAULT_BITS_PER_LINE = 32  # Number of bits per line
    _DEFAULT_DO_PRINT_TOP_TENS = True  # True: print top numbers for bit tens
    _DEFAULT_DO_PRINT_TOP_UNITS = True  # True: print top numbers for bit units

    def __init__(self, specification: str) -> None:
        """Initialize the `Protocol` object.
        
        Parameters
        ----------
        specification : str
            The textual specification that describes the protocol.
        """
        self._hdr_char_start: str = Protocol._DEFAULT_HDR_CHAR_START
        self._hdr_char_end: str = Protocol._DEFAULT_HDR_CHAR_END
        self._hdr_char_fill_odd: str = Protocol._DEFAULT_HDR_CHAR_FILL_ODD
        self._hdr_char_fill_even: str = Protocol._DEFAULT_HDR_CHAR_FILL_EVEN
        self._hdr_char_sep: str = Protocol._DEFAULT_HDR_CHAR_SEP
        self._bits_per_line: int = Protocol._DEFAULT_BITS_PER_LINE
        self._do_print_top_tens: bool = Protocol._DEFAULT_DO_PRINT_TOP_TENS
        self._do_print_top_units: bool = Protocol._DEFAULT_DO_PRINT_TOP_UNITS
        self._field_list: list[dict[str, str | int]]  = []
        self._parse_spec(specification=specification)


    def _parse_spec(self, specification: str) -> None:
        """Parse the textual protocol specification and store the relevant internal states for later ASCII conversion.
        
        Parameters
        ----------
        specification : str
            The textual specification that describes the protocol.
        """
        if "?" in specification:
            parts = specification.split("?")
            fields = parts[0]
            opts = parts[1]
            if specification.count("?") > 1:
                err_msg = "FATAL: Character '?' may only be used as an option separator."
                raise ProtocolException(err_msg)
        else:
            fields = specification
            opts = None

        # Parse field specification
        items = fields.split(",")
        for item in items:
            try:
                text, bits = item.split(":")
                bits = int(bits)
                if bits <= 0:
                    err_msg = f"FATAL: Fields must be at least one bit long ({specification})"
                    raise ProtocolException(err_msg)
            except Exception as err:
                err_msg = f"FATAL: Invalid field_list specification ({specification})"
                raise ProtocolException(err_msg) from err
            self._field_list.append({"text": text, "len": bits})

        # Parse options
        if opts is not None:
            opts = opts.split(",")
            for opt in opts:
                try:
                    var, value = opt.split("=")
                    if var.lower() == "bits":
                        self._bits_per_line = int(value)
                        if self._bits_per_line <= 0:
                            err_msg = f"FATAL: Invalid value for 'bits' option ({value})"
                            raise ProtocolException(err_msg)
                    elif var.lower() == "numbers":
                        if value.lower() in ["0", "n", "no", "none", "false"]:
                            self._do_print_top_tens = False
                            self._do_print_top_units = False
                        elif value.lower() in ["1", "y", "yes", "none", "true"]:
                            self._do_print_top_tens = True
                            self._do_print_top_units = True
                        else:
                            raise ProtocolException("FATAL: Invalid value for 'numbers' option (%s)" % value)
                    elif var.lower() in ["oddchar", "evenchar", "startchar", "endchar", "sepchar"]:
                        if len(value) > 1 or len(value) <= 0:
                            raise ProtocolException("FATAL: Invalid value for '%s' option (%s)" % (var, value))
                        else:
                            if var.lower() == "oddchar":
                                self._hdr_char_fill_odd = value
                            elif var.lower() == "evenchar":
                                self._hdr_char_fill_even = value
                            elif var.lower() == "startchar":
                                self._hdr_char_start = value
                            elif var.lower() == "endchar":
                                self._hdr_char_end = value
                            elif var.lower() == "sepchar":
                                self._hdr_char_sep = value
                except ProtocolException:
                    raise
                except:
                    raise ProtocolException("FATAL: Invalid options specification (%s)" % opt)

        return self._field_list

    def _get_top_numbers(self):
        """
        @return a string representing the bit units and bit tens on top of the
        protocol header. Note that a proper string is only returned if one or
        both self._do_print_top_tens and self._do_print_top_units is True.
        The returned string is not \n terminated, but it may contain a newline
        character in the middle.
        """
        lines = ["", ""]
        if self._do_print_top_tens is True:
            for i in range(0, self._bits_per_line):
                if str(i)[-1:] == "0":
                    lines[0] += " %s" % str(i)[0]
                else:
                    lines[0] += "  "
            lines[0] += "\n"
        if self._do_print_top_units is True:
            for i in range(0, self._bits_per_line):
                lines[1] += " %s" % str(i)[-1:]
            # lines[1]+="\n"
        result = "".join(lines)
        return result if len(result) > 0 else None

    def _get_horizontal(self, width=None):
        """
        @return the horizontal border line that separates field rows.
        @param width controls how many field bits the line should cover. By
        default, if no width is supplied, the line covers the hole length of
        the header.
        """
        if width is None:
            width = self._bits_per_line
        if width <= 0:
            return ""
        else:
            a = "%s" % self._hdr_char_start
            b = (self._hdr_char_fill_even + self._hdr_char_fill_odd) * (width - 1)
            c = "%s%s" % (self._hdr_char_fill_even, self._hdr_char_end)
            return a + b + c

    def _get_separator(self, line_end=""):
        """
        @return a string containing a protocol field separator. Returned string
        is a single character and matches whatever is stored in self._hdr_char_sep
        """
        return self._hdr_char_sep

    def _process_field_list(self):
        """
        Processes the list of protocol fields that we got from the specification and turns
        it into something that we can print easily (useful for cases when we have
        protocol fields that span more than one line). This is just a helper
        function to make __str__()'s life easier.
        """
        new_fields = []
        bits_in_line = 0
        i = 0
        while i < len(self._field_list):
            # Extract all the info we need about the field
            field = self._field_list[i]
            field_text = field["text"]
            field_len = field["len"]
            field["MF"] = False

            available_in_line = self._bits_per_line - bits_in_line

            # If we have enough space on this line to include the current field
            # then just keep it as it is.
            if available_in_line >= field_len:
                new_fields.append(field)
                bits_in_line += field_len
                i += 1
                if bits_in_line == self._bits_per_line:
                    bits_in_line = 0
            # Otherwise, split the field into two parts, one blank and one with
            # the actual field text
            else:
                # Case 1: We have a field that is perfectly aligned and it
                # has a length that is multiple of our line length
                if bits_in_line == 0 and field_len % self._bits_per_line == 0:
                    new_fields.append(field)
                    i += 1
                    bits_in_line = 0

                # Case 2: We weren't that lucky and the field is either not
                # aligned or we can't print it using an exact number of full
                # lines
                else:
                    # If we have more space in the current line than in the next,
                    # then put the field text in this one
                    if available_in_line >= field_len - available_in_line:
                        new_field = {"text": field_text, "len": available_in_line, "MF": True}
                        new_fields.append(new_field)
                        field["text"] = ""
                        field["len"] = field_len - available_in_line
                        field["MF"] = False
                    else:
                        new_field = {"text": "", "len": available_in_line, "MF": True}
                        new_fields.append(new_field)
                        field["text"] = field_text
                        field["len"] = field_len - available_in_line
                        field["MF"] = False
                    bits_in_line = 0
                    continue
        return new_fields

    # Convert to string
    def __str__(self):
        """
        Converts the protocol specification stored in the object to a nice
        ASCII diagram like the ones that appear in RFCs. Conversion supports
        fields of any length, and supports field that span more than one
        line in the diagram.
        @return a string containing the ASCII representation of the protocol
        header.
        """

        # First of all, process our field list. This does some magic to make
        # the algorithm work for fields that span more than one line
        proto_fields = self._process_field_list()
        lines = []
        numbers = self._get_top_numbers()
        if numbers is not None:
            lines.append(numbers)
        lines.append(self._get_horizontal())

        # Print all protocol fields
        bits_in_line = 0
        current_line = ""
        fields_done = 0
        p = -1
        while p < len(proto_fields) - 1:
            p += 1

            # Extract all the info we need about the field
            field = proto_fields[p]
            field_text = field["text"]
            field_len = field["len"]
            field_mf = field["MF"] is True  # Field has more fragments

            # If the field text is too long, we truncate it, and add a dot
            # at the end.
            if len(field_text) > (field_len * 2) - 1:
                field_text = field_text[0 : (field_len * 2) - 1]
                if len(field_text) > 1:
                    field_text = field_text[0:-1] + "."

            # If we have space for the whole field in the current line, go
            # ahead and add it
            if self._bits_per_line - bits_in_line >= field_len:
                # If this is the first thing we print on a line, add the
                # starting character
                if bits_in_line == 0:
                    current_line += self._get_separator()

                # Add the whole field
                current_line += str.center(field_text, (field_len * 2) - 1)

                # Update counters
                bits_in_line += field_len
                fields_done += 1

                # If this is the last character in the line, store the line
                if bits_in_line == self._bits_per_line:
                    current_line += self._get_separator()
                    lines.append(current_line)
                    current_line = ""
                    bits_in_line = 0
                    # When we have a fragmented field, we may need to suppress
                    # the floor of the field, so the current line connects
                    # with the one that follows. E.g.:
                    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    # |            field16            |                               |
                    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
                    # |                             field                             |
                    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    if field_mf is True:
                        if proto_fields[p + 1]["len"] > self._bits_per_line - field_len:
                            # Print some +-+-+ to cover the previous field
                            line_left = self._get_horizontal(self._bits_per_line - field_len)
                            if len(line_left) == 0:
                                line_left = self._hdr_char_start

                            # Now print some empty space to cover the part that
                            # we can join with the field below.
                            # Case 1: If the next field reaches the end of its
                            # line, then we need to print whitespace until the
                            # end our line
                            if proto_fields[p + 1]["len"] >= self._bits_per_line:
                                line_center = " " * (2 * (field_len) - 1)
                                line_right = self._hdr_char_end
                            # Case 2: the field in the next row is not big enough
                            # to cover all the space we'd like to join, so we
                            # just print whitespace to cover as much as we can
                            else:
                                line_center = " " * (
                                    (2 * (proto_fields[p + 1]["len"] - (self._bits_per_line - field_len))) - 1
                                )
                                line_right = self._get_horizontal(self._bits_per_line - proto_fields[p + 1]["len"])

                            lines.append(line_left + line_center + line_right)
                        else:
                            lines.append(self._get_horizontal())
                    else:
                        lines.append(self._get_horizontal())

                # If this is not the last character of the line but we have no
                # more fields to print, wrap up
                elif fields_done == len(proto_fields):
                    current_line += self._get_separator()
                    lines.append(current_line)
                    lines.append(self._get_horizontal(bits_in_line))
                else:
                    # Add the separator character
                    current_line += self._hdr_char_sep

            # We don't have enough space for the field on this line.
            else:
                # Case 1: We are at the beginning of a new line and we need to
                # span more than one line
                if bits_in_line == 0:
                    # Case 1a: We have a multiple of the number of bits per line
                    if field_len % self._bits_per_line == 0:
                        # Compute how many lines in total we need to print for this
                        # big field.
                        lines_to_print = int(((field_len / self._bits_per_line) * 2) - 1)
                        # We print the field text in the central line
                        central_line = int(lines_to_print / 2)
                        # Print all those lines
                        for i in range(0, lines_to_print):
                            # Let's figure out which character we need to use
                            # to start and end the current line
                            if i % 2 == 1:
                                start_line = self._hdr_char_start
                                end_line = self._hdr_char_end
                            else:
                                start_line = self._hdr_char_sep
                                end_line = self._hdr_char_sep

                            # This is the line where we need to print the field
                            # text.
                            if i == central_line:
                                lines.append(
                                    start_line + str.center(field_text, (self._bits_per_line * 2) - 1) + end_line
                                )
                            # This is a line we need to leave blank
                            else:
                                lines.append(start_line + (" " * ((self._bits_per_line * 2) - 1)) + end_line)
                            # If we just added the last line, add a horizontal separator
                            if i == lines_to_print - 1:
                                lines.append(self._get_horizontal())

                # Case 2: We are not at the beginning of the line and we need
                # to print something that does not fit in the current line
                else:
                    # This should never happen, since our _process_field_list()
                    # divides fields in chunks so we never have the case of
                    # something spanning lines in a weird manner
                    assert False

        result = "\n".join(lines)
        return result
