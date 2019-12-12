# pkt_decoder
My attempt at a packet decoder problem.

Problem definition:
The assignment is to write a small library that acts as a packet framer/decoder. The library
should implement the pkt_decoder.h file. There are three entry points: pkt_decoder_create(),
pkt_decoder_destroy(), pkt_decoder_write_bytes(). Clients pass a stream of bytes to the library
by calling pkt_decoder_write_bytes one or more times. The library finds framed packets, and
invokes the callback passed in with the data of the decoded packet (as well as the passed in
void* callback_ctx) on successful decoding. Thread safety between the reader and writer
interfaces is a non goal; you can assume that they are on the same thread.

Framing protocol:
The byte stream being written to pkt_decoder_write_bytes() is encoded via a simple framing
protocol. Packets start with 0x02 (STX) and end with 0x03 (ETX). If an 0x02 or 0x03 appears
inside a packet it is escaped with the tuple (0x10, 0x20 | value), where ‘|’ is a bitwise or.
If an 0x10 (DLE) appears in the stream, it is escaped the same way (ie. (0x10, 0x20 |
0x10)). If the decoded data in a packet is longer than MAX_DECODED_DATA_LEN (512), the
packet is considered invalid.
Frames that are incomplete or improperly encoded should be silently dropped.

Solution Assumptions:

1. We limit the size of the decoded output to 512 bytes. This means packets with encoding such that data past 512 bytes
    may be valid are deemed invalid. The reason here is to ensure we do not run out of memory for cases like:
    a packet with stx, and data with no etx.
    2. We assume that a packet is invalid if a packet has something other than 22,33,30 following a 0x10. i.e we
    only expect STX/ETX/DLE bitwise or'ed with 0x20 following a DLE.

