"""The main entrypoint to the protocol package."""

from __future__ import annotations

import argparse

import protocol
from protocol import __about__, specs


def __protocol(raw_protocol: str) -> protocol.Protocol:
    """Parse the specification received from the command line into a `Protocol` object.

    Parameters
    ----------
    raw_protocol : str
        The specification received from the command line.

    Returns
    -------
    protocol.Protocol
        The `Protocol` object loaded with the specification.

    Raises
    ------
    argparse.ArgumentError
        A non-custom specification was provided that does not exist.
    argparse.ArgumentError
        A non-custom specification was provided that is too ambiguous.
    argparse.ArgumentError
        An invalid custom specification was provided.
    """
    # Assume it's a custom protocol if it contains a ":"
    if raw_protocol.count(":") > 0:
        spec = raw_protocol
    elif raw_protocol in specs.PROTOCOLS:
        spec = specs.PROTOCOLS[raw_protocol]
    else:
        similar_specs: list[str] = [s for s in specs.PROTOCOLS if s.startswith(raw_protocol)]
        
        if len(similar_specs) == 0:
            err_msg = f"The protocol '{raw_protocol}' does not exist."
            raise argparse.ArgumentError(None, err_msg)
        if len(similar_specs) != 1:
            err_msg = f"Ambiguous protocol specifier '{raw_protocol}'. Did you mean one of these?\n{'  \n'.join(similar_specs)}"
            raise argparse.ArgumentError(None, err_msg)
            
        # If there's only one similar spec, assume that's what they're going for
        spec = specs.PROTOCOLS[similar_specs[0]]

    try:
        return protocol.Protocol(specification=spec)
    except protocol.ProtocolError as err:
        raise argparse.ArgumentError(None, str(err)) from err


def __parse_args() -> argparse.Namespace:
    """Parse the command-line arguments.

    Returns
    -------
    argparse.Namespace
        The parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description=__about__.__summary__)
    parser.add_argument("protocol", type=__protocol, nargs="+", help="the name of an existing protocol, or a field-by-field specification of a custom protocol")
    parser.add_argument("-v", "--version", action="version", version=f"{__about__.__title__} v{__about__.__version__}")
    parser.add_argument("-b", "--bits", type=int, required=False, help="the number of bits per line")
    parser.add_argument("-n", "--no-numbers", action="store_true", help="do not print bit numbers on top of the header")
    parser.add_argument("--evenchar", type=str, required=False, help="character for the even positions of horizontal table borders")
    parser.add_argument("--oddchar", type=str, required=False, help="character for the odd positions of horizontal table borders")
    parser.add_argument("--startchar", type=str, required=False, help="character that starts horizontal table borders")
    parser.add_argument("--endchar", type=str, required=False, help="character that ends horizontal table borders")
    parser.add_argument("--sepchar", type=str, required=False, help="character that separates protocol fields")
    return parser.parse_args()


def main() -> None:
    """Run the protocol program."""
    args = __parse_args()

    # Print every protocol given, modifying any settings provided
    protocols: list[protocol.Protocol] = args.protocol
    for proto in protocols:
        if args.bits is not None:
            proto.bits_per_line = args.bits
        proto.print_top_tens = not args.no_numbers
        proto.print_top_units = not args.no_numbers
        if args.evenchar is not None:
            proto.even_fill_chr = args.evenchar
        if args.oddchar is not None:
            proto.odd_fill_chr = args.oddchar
        if args.startchar is not None:
            proto.start_chr = args.startchar
        if args.endchar is not None:
            proto.end_chr = args.endchar
        if args.sepchar is not None:
            proto.separator_chr = args.sepchar
        print(proto, end="\n\n")


if __name__ == "__main__":
    main()
