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


__all__ = ("Protocol", "ProtocolError")


class ProtocolError(Exception):
    """Class for exceptions raised by the `Protocol` class."""

    def __init__(self, err_msg: str) -> None:
        """Initialize the `ProtocolError` object.

        Parameters
        ----------
        err_msg : str
            The error message of the exception.
        """
        self.__err_msg = err_msg

    def __str__(self) -> str:
        """Get the string representation of the `ProtocolError` object.

        Returns
        -------
        str
            The string representation of the `ProtocolError` object.
        """
        return self.__err_msg


class Protocol:
    """Class representing a network protocol header.

    Objects are constructed by passing a textual protocol specification. Once that is done, instances can be printed by
    converting them to a `str` type.
    """

    def __init__(self, specification: str) -> None:
        """Initialize the `Protocol` object.

        Parameters
        ----------
        specification : str
            The textual specification that describes the protocol.
        """
        self.__start_chr: str = "+"
        self.__end_chr: str = "+"
        self.__odd_fill_chr: str = "+"
        self.__even_fill_chr: str = "-"
        self.__separator_chr: str = "|"
        self.__bits_per_line: int = 32
        self.__print_top_tens: bool = True
        self.__print_top_units: bool = True
        self.__field_list: list[dict[str, str | int | bool]] = []
        self.__parse_spec(specification=specification)

    @property
    def start_chr(self) -> str:
        """Get the character for the start of the border line.

        Returns
        -------
        str
            The character for the start of the border line.
        """
        return self.__start_chr

    @property
    def end_chr(self) -> str:
        """Get the character for the end of the border line.

        Returns
        -------
        str
            The character for the end of the border line.
        """
        return self.__end_chr

    @property
    def odd_fill_chr(self) -> str:
        """Get the fill character for the odd-positioned border.

        Returns
        -------
        str
            The fill character for the odd-positioned border.
        """
        return self.__odd_fill_chr

    @property
    def even_fill_chr(self) -> str:
        """Get the fill character for the even-positioned border.

        Returns
        -------
        str
            The fill character for the even-positioned border.
        """
        return self.__even_fill_chr

    @property
    def separator_chr(self) -> str:
        """Get the field separator character.

        Returns
        -------
        str
            The field separator character.
        """
        return self.__separator_chr

    @property
    def bits_per_line(self) -> int:
        """Get the number of bits per line.

        Returns
        -------
        int
            The number of bits per line.
        """
        return self.__bits_per_line

    @property
    def print_top_tens(self) -> bool:
        """Get the flag indicating whether to print header numbers for every ten bits.

        Returns
        -------
        bool
            True to print header numbers for every ten bits, False to not print them.
        """
        return self.__print_top_tens

    @property
    def print_top_units(self) -> bool:
        """Get the flag indicating whether to print the bit units.

        Returns
        -------
        bool
            True to print the bit units, False to not print them.
        """
        return self.__print_top_units

    @start_chr.setter
    def start_chr(self, start_chr: str) -> None:
        """Set the character for the start of the border line.

        Parameters
        ----------
        start_chr : str
            The character for the start of the border line.

        Raises
        ------
        TypeError
            The value is not a 'str' object.
        """
        if not isinstance(start_chr, str):
            err_msg = "invalid type for start character, must be a 'str'"
            raise TypeError(err_msg)
        self.__start_chr = start_chr

    @end_chr.setter
    def end_chr(self, end_chr: str) -> None:
        """Set the character for the end of the border line.

        Parameters
        ----------
        end_chr : str
            The character for the end of the border line.

        Raises
        ------
        TypeError
            The value is not a 'str' object.
        """
        if not isinstance(end_chr, str):
            err_msg = "invalid type for end character, must be a 'str'"
            raise TypeError(err_msg)
        self.__end_chr = end_chr

    @odd_fill_chr.setter
    def odd_fill_chr(self, odd_fill_chr: str) -> None:
        """Set the fill character for the odd-positioned border.

        Parameters
        ----------
        odd_fill_chr : str
            The fill character for the odd-positioned border.

        Raises
        ------
        TypeError
            The value is not a 'str' object.
        """
        if not isinstance(odd_fill_chr, str):
            err_msg = "invalid type for odd fill character, must be a 'str'"
            raise TypeError(err_msg)
        self.__odd_fill_chr = odd_fill_chr

    @even_fill_chr.setter
    def even_fill_chr(self, even_fill_chr: str) -> None:
        """Set the fill character for the even-positioned border.

        Parameters
        ----------
        even_fill_chr : str
            The fill character for the even-positioned border.

        Raises
        ------
        TypeError
            The value is not a 'str' object.
        """
        if not isinstance(even_fill_chr, str):
            err_msg = "invalid type for even fill character, must be a 'str'"
            raise TypeError(err_msg)
        self.__even_fill_chr = even_fill_chr

    @separator_chr.setter
    def separator_chr(self, separator_chr: str) -> None:
        """Set the field separator character.

        Parameters
        ----------
        separator_chr : str
            The field separator character.

        Raises
        ------
        TypeError
            The value is not a 'str' object.
        """
        if not isinstance(separator_chr, str):
            err_msg = "invalid type for separator character, must be a 'str'"
            raise TypeError(err_msg)
        self.__separator_chr = separator_chr

    @bits_per_line.setter
    def bits_per_line(self, bits_per_line: int) -> None:
        """Set the number of bits per line.

        Parameters
        ----------
        bits_per_line : int
            The number of bits per line.

        Raises
        ------
        TypeError
            The value is not an 'int' object.
        """
        if not isinstance(bits_per_line, int):
            err_msg = "invalid type for bits per line, must be an 'int'"
            raise TypeError(err_msg)
        self.__bits_per_line = bits_per_line

    @print_top_tens.setter
    def print_top_tens(self, print_top_tens: bool) -> None:
        """Set the flag indicating whether to print header numbers for every ten bits.

        Parameters
        ----------
        print_top_tens : bool
            True to print header numbers for every ten bits, False to not print them.

        Raises
        ------
        TypeError
            The value is not a 'bool' object.
        """
        if not isinstance(print_top_tens, bool):
            err_msg = "invalid type for print top tens flag, must be a 'bool'"
            raise TypeError(err_msg)
        self.__print_top_tens = print_top_tens

    @print_top_units.setter
    def print_top_units(self, print_top_units: bool) -> None:
        """Set the flag indicating whether to print the bit units.

        Parameters
        ----------
        print_top_units : bool
            True to print the bit units, False to not print them.

        Raises
        ------
        TypeError
            The value is not a 'bool' object.
        """
        if not isinstance(print_top_units, bool):
            err_msg = "invalid type for print top units flag, must be a 'bool'"
            raise TypeError(err_msg)
        self.__print_top_units = print_top_units

    def __parse_spec(self, specification: str) -> None:  # noqa: C901, PLR0912, PLR0915
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
                err_msg = "character '?' may only be used as an option separator"
                raise ProtocolError(err_msg)
        else:
            fields = specification
            opts = None

        # Parse field specification
        items = fields.split(",")
        for item in items:
            try:
                text, bits = item.split(":")
                bits = int(bits)
            except ValueError as err:
                err_msg = f"invalid field_list specification ({specification})"
                raise ProtocolError(err_msg) from err
            if bits <= 0:
                err_msg = f"fields must be at least one bit long ({specification})"
                raise ProtocolError(err_msg)

            self.__field_list.append({"text": text, "len": bits})

        # Parse options
        if opts is not None:
            opts = opts.split(",")
            for opt in opts:
                try:
                    var, value = opt.split("=")
                except ValueError as err:
                    err_msg = f"invalid options specification ({opt})"
                    raise ProtocolError(err_msg) from err
                if var.lower() == "bits":
                    try:
                        self.__bits_per_line = int(value)
                    except ValueError as err:
                        err_msg = f"invalid options specification ({opt})"
                        raise ProtocolError(err_msg) from err
                    if self.__bits_per_line <= 0:
                        err_msg = f"invalid value for 'bits' option ({value})"
                        raise ProtocolError(err_msg)
                elif var.lower() == "numbers":
                    if value.lower() in ["0", "n", "no", "none", "false"]:
                        self.__print_top_tens = False
                        self.__print_top_units = False
                    elif value.lower() in ["1", "y", "yes", "none", "true"]:
                        self.__print_top_tens = True
                        self.__print_top_units = True
                    else:
                        err_msg = f"invalid value for 'numbers' option ({value})"
                        raise ProtocolError(err_msg)
                elif var.lower() in ["oddchar", "evenchar", "startchar", "endchar", "sepchar"]:
                    if len(value) > 1 or len(value) <= 0:
                        err_msg = f"invalid value for '{var}' option ({value})"
                        raise ProtocolError(err_msg)
                    if var.lower() == "oddchar":
                        self.__odd_fill_chr = value
                    elif var.lower() == "evenchar":
                        self.__even_fill_chr = value
                    elif var.lower() == "startchar":
                        self.__start_chr = value
                    elif var.lower() == "endchar":
                        self.__end_chr = value
                    elif var.lower() == "sepchar":
                        self.__separator_chr = value

    def __get_top_numbers(self) -> str | None:
        r"""Get the string representing the bit units and bit tens on top of the protocol header.

        Returns
        -------
        str
            The string representing the bit units and bit tens on top of the protocol header, or None if there is none.

        Notes
        -----
        A proper string is only returned if one or both of `self.__print_top_tens` and `self.__print_top_units` is
        True. The returned string is not '\n' terminated, but it may contain one in the middle.
        """
        lines = ["", ""]
        if self.__print_top_tens:
            for i in range(self.__bits_per_line):
                if str(i)[-1:] == "0":
                    lines[0] += f" {str(i)[0]}"
                else:
                    lines[0] += "  "
            lines[0] += "\n"
        if self.__print_top_units:
            for i in range(self.__bits_per_line):
                lines[1] += f" {str(i)[-1:]}"
        result = "".join(lines)
        return result if len(result) > 0 else None

    def __get_horizontal(self, width: int | None = None) -> str:
        """Get the horizontal border line that separates field rows.

        Parameters
        ----------
        width : int | None, optional
            The number of field bits the line should cover, or None to cover the entire length of the header, by default
            None.
        """
        width = self.__bits_per_line if width is None else width
        if width <= 0:
            return ""
        return (
            self.__start_chr
            + ((self.__even_fill_chr + self.__odd_fill_chr) * (width - 1))
            + self.__even_fill_chr
            + self.__end_chr
        )

    def __process_field_list(self) -> list[dict[str, str | int | bool]]:
        """Process the list of protocol fields in the specification into printable output.

        Returns
        -------
        dist[str, str | int | bool]
            The list of protocol fields in an easily printable format.
        """
        new_fields: list[dict[str, str | int | bool]] = []
        bits_in_line = 0
        i = 0
        while i < len(self.__field_list):
            # Extract all the info we need about the field
            field = self.__field_list[i]
            field_text: str = field["text"]
            field_len: int = field["len"]
            field["MF"] = False

            available_in_line = self.__bits_per_line - bits_in_line

            # If we have enough space on this line to include the current field then just keep it as it is.
            if available_in_line >= field_len:
                new_fields.append(field)
                bits_in_line += field_len
                i += 1
                if bits_in_line == self.__bits_per_line:
                    bits_in_line = 0
            # Otherwise, split the field into two parts, one blank and one with the actual field text
            # Case 1: field that is perfectly aligned and has a length that is multiple of line length
            elif bits_in_line == 0 and field_len % self.__bits_per_line == 0:
                new_fields.append(field)
                i += 1
                bits_in_line = 0

            # Case 2:  field is either not aligned or we can't print it using an exact number of full lines
            else:
                # If we have more space in the current line than in the next, then put the field text in this one
                if available_in_line >= field_len - available_in_line:
                    new_field: dict[str, str | int | bool] = {
                        "text": field_text,
                        "len": available_in_line,
                        "MF": True,
                    }
                    new_fields.append(new_field)
                    field["text"] = ""
                    field["len"] = field_len - available_in_line
                    field["MF"] = False
                else:
                    new_field: dict[str, str | int | bool] = {"text": "", "len": available_in_line, "MF": True}
                    new_fields.append(new_field)
                    field["text"] = field_text
                    field["len"] = field_len - available_in_line
                    field["MF"] = False
                bits_in_line = 0
                continue
        return new_fields

    def __str__(self) -> str:  # noqa: C901, PLR0912, PLR0915
        """Get the ASCII representation of the protocol specification.

        Returns
        -------
        str
            The ASCII representation of the protocol specification.
        """
        # Process our field list to make the algorithm work for fields that span more than one line
        proto_fields = self.__process_field_list()
        lines: list[str] = []
        if (numbers := self.__get_top_numbers()) is not None:
            lines.append(numbers)
        lines.append(self.__get_horizontal())

        # Print all protocol fields
        bits_in_line = 0
        current_line = ""
        fields_done = 0
        p = -1
        while p < len(proto_fields) - 1:
            p += 1

            # Extract all the info we need about the field
            field = proto_fields[p]
            field_text: str = field["text"]
            field_len: int = field["len"]
            field_mf: bool = field["MF"]

            # If the field text is too long, we truncate it, and add a "." at the end.
            if len(field_text) > (field_len * 2) - 1:
                field_text = field_text[0 : (field_len * 2) - 1]
                if len(field_text) > 1:
                    field_text = field_text[0:-1] + "."

            # If we have space for the whole field in the current line, go ahead and add it
            if self.__bits_per_line - bits_in_line >= field_len:
                # If this is the first thing we print on a line, add the starting character
                if bits_in_line == 0:
                    current_line += self.__separator_chr

                # Add the whole field
                current_line += field_text.center((field_len * 2) - 1)

                # Update counters
                bits_in_line += field_len
                fields_done += 1

                # If this is the last character in the line, store the line
                if bits_in_line == self.__bits_per_line:
                    current_line += self.__separator_chr
                    lines.append(current_line)
                    current_line = ""
                    bits_in_line = 0
                    # When we have a fragmented field, we may need to suppress the floor of the field, so the current
                    # line connects with the one that follows. E.g.:
                    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    # |            field16            |                               |
                    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
                    # |                             field                             |
                    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    if field_mf:
                        if proto_fields[p + 1]["len"] > self.__bits_per_line - field_len:
                            # Print some +-+-+ to cover the previous field
                            line_left = self.__get_horizontal(self.__bits_per_line - field_len)
                            if len(line_left) == 0:
                                line_left = self.__start_chr

                            # Now print some empty space to cover the part that we can join with the field below.
                            # Case 1: If the next field reaches the end of its line, then we need to print whitespace
                            # until the end our line
                            if proto_fields[p + 1]["len"] >= self.__bits_per_line:
                                line_center = " " * (2 * (field_len) - 1)
                                line_right = self.__end_chr
                            # Case 2: the field in the next row is not big enough to cover all the space we'd like to
                            # join, so we just print whitespace to cover as much as we can
                            else:
                                line_center = " " * (
                                    (2 * (proto_fields[p + 1]["len"] - (self.__bits_per_line - field_len))) - 1
                                )
                                line_right = self.__get_horizontal(self.__bits_per_line - proto_fields[p + 1]["len"])

                            lines.append(line_left + line_center + line_right)
                        else:
                            lines.append(self.__get_horizontal())
                    else:
                        lines.append(self.__get_horizontal())

                # If this is not the last character of the line but we have no more fields to print, wrap up
                elif fields_done == len(proto_fields):
                    current_line += self.__separator_chr
                    lines.append(current_line)
                    lines.append(self.__get_horizontal(bits_in_line))
                else:
                    # Add the separator character
                    current_line += self.__separator_chr

            # We don't have enough space for the field on this line.
            # Case 1: We are at the beginning of a new line and we need to span more than one line
            elif bits_in_line == 0:
                # Case 1a: We have a multiple of the number of bits per line
                if field_len % self.__bits_per_line == 0:
                    # Compute how many lines in total we need to print for this big field.
                    lines_to_print = int(((field_len / self.__bits_per_line) * 2) - 1)
                    # We print the field text in the central line
                    central_line = int(lines_to_print / 2)
                    # Print all those lines
                    for i in range(lines_to_print):
                        # Let's figure out which character we need to use to start and end the current line
                        if i % 2 == 1:
                            start_line = self.__start_chr
                            end_line = self.__end_chr
                        else:
                            start_line = self.__separator_chr
                            end_line = self.__separator_chr

                        # This is the line where we need to print the field
                        # text.
                        if i == central_line:
                            lines.append(start_line + str.center(field_text, (self.__bits_per_line * 2) - 1) + end_line)
                        # This is a line we need to leave blank
                        else:
                            lines.append(start_line + (" " * ((self.__bits_per_line * 2) - 1)) + end_line)
                        # If we just added the last line, add a horizontal separator
                        if i == lines_to_print - 1:
                            lines.append(self.__get_horizontal())

            # Case 2: We are not at the beginning of the line and we need to print something that does not fit in the
            # current line
            else:
                # This should never happen, since our `__process_field_list()` divides fields in chunks so we never have
                # the case of something spanning lines in a weird manner
                err_msg = "this should never occur"
                raise AssertionError(err_msg)

        return "\n".join(lines)
