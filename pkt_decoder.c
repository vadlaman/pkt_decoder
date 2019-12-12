#include "pkt_decoder.h"

#include <stdio.h>

// Callback function to print the decoded packet data and its length
static void pkt_printer(void *ctx, size_t data_length, const uint8_t *data) {
(void)ctx;
printf("pkt (%zd bytes) -", data_length);
for(size_t i = 0; i < data_length; i++) {
printf(" %02x", data[i]);
}
printf("\n");
}

// Create a pkt_decoder structure and initialize with values and return it
pkt_decoder_t* pkt_decoder_create(pkt_read_fn_t callback, void *callback_ctx)
{
  pkt_decoder_t *decoder;
  // Allocate memory for the decoder
  decoder = (pkt_decoder_t *) malloc(sizeof(pkt_decoder_t));
  // set the function pointer with the callback function that is passed in
  decoder->funcallback = callback;
  // Set default values for rest of the members
  decoder->length = 0;
  decoder->stx_seen = false;
  decoder->cur_stx_index = 0;
  decoder->invalid = false;
  decoder->complete = false;

  // return decoder structure
  return decoder;
}

// Called on incoming, undecoded bytes to be translated into packets
// Here are my assumptions for creating a decoded packet
// 1. We limit the size of the decoded output to 512 bytes. This means packets
// with encoding such that data past 512 bytes may be valid are deemed invalid.
// The reason here is to ensure we do not run out of memory for a case like
// a packet with stx, and data with no etx.
// 2. We assume that a packet is invalid if a packet has something
// other than 22,33,30 following a 0x10. i.e we only expect
// STX/ETX/DLE bitwise or'ed with 0x20 following a DLE.

void pkt_decoder_write_bytes(pkt_decoder_t *decoder,
                            size_t len, const uint8_t *data)
{
  // A local variable to check if an 0x10(DLE) appears in the stream.
  // If a DLE is seen set ignore to true.
  static bool ignore = false;

  // if the invalid field in the decoder struct is set to true then return as
  // the incoming data is either improperly encoded or the packet data is
  // longer than MAX_DECODED_DATA_LENGTH
  if (decoder->invalid) {
    return;
  }

  // Iterate through the lenght of the encoded data and capture the decoded data
  for (size_t i = 0; i < len; i++) {

    // check to see if the ignore is set to true, which means we have seen 0x10
    // then set ignore back to false and continue.
    if (ignore) {
      ignore = false;
      continue;
    }

    // If decoded data packet length is greater than MAX_DECODED_DATA_LENGTH
    // then set invalid to true and set complete to false and return as there is
    // nothing to do.
    if (decoder->length > MAX_DECODED_DATA_LENGTH)
    {
      decoder->invalid = true;
      decoder->complete = false;
      return;
    }

    // Check if 0x02(STX) appears in the stream. If STX is seen,
    // set the stx_seen flag to true.
    if (!(decoder->stx_seen) && (data[i] != 0x02)) {
      continue;
    }
    decoder->stx_seen = true;

    // Check if 0x03(ETX) appears in the stream. If ETX is seen, that means
    // we have to set complete to true as the packet is complete and reset
    // stx_seen to false and cur_stx_index to the lenght
    if (data[i] == 0x03) {
      decoder ->complete = true;
      decoder->stx_seen = false;
      decoder->cur_stx_index = decoder->length;
      continue;
    }

    // Check to see if another 0x02 is seen after STX is seen. If seen,
    // set complete to false and set back the lenght to cur_stx_index.
    if (data[i] == 0x02) {
      decoder->complete = false;
      decoder->length = decoder->cur_stx_index;
      continue;
    }

    // Special cases when 0x10(DLE) appears in the stream
    // followed by a DLE encoded value. We ignore the 0x10 and
    // decode the DLE encoded values to store them.
    // Valid values are 0x22, 0x23, and 0x30. These values are equivalent to
    // DLE encoded 0x02, 0x03, and 0x10 respectively.
    if (data[i] == 0x10) {
      ignore = true;
      // ignore the current byte and move onto the next one
      if (data[i+1] == 0x22) {
        decoder->pkt_data[decoder->length] = 0x02;
        decoder->length++;
      }

      else if (data[i+1] == 0x23) {
        decoder->pkt_data[decoder->length] = 0x03;
        decoder->length++ ;
        }

      else if (data[i+1] == 0x30) {
        decoder->pkt_data[decoder->length] = 0x10;
        decoder->length++;
      }
      else {
        // we cannot expect any other value other than 0x02, 0x03, or 0x10
        // followed by a DLE
        decoder->invalid = true;
      }
      continue;
    }

    // Store the decoded data in decoder struct
    decoder->pkt_data[decoder->length] = data[i];
    decoder->length++;
  }
}

// packet decoder destroy
void pkt_decoder_destroy(pkt_decoder_t *decoder)
{
  // check if the complete flag is set to true, which means packets were
  // successfully decoded and stored in the decoder struct.
  // If complete is true call the callback function. In this case, it is the
  // print function. pass in the data and the lenght of the data
  // stored in the decoder struct.
  if(decoder->complete) {
    decoder->funcallback(NULL, decoder->length, decoder->pkt_data);
  }
  // once all the work is done by the callback functions,
  // free the decoder struct.
  free(decoder);
}


int main() {
// Test with various packets
// A single packet containing 0xFF as data.
// output: ff
const uint8_t pkt1[] = {0x02, 0xFF, 0x03};
// A single packet containing 0x02 encoded using the DLE scheme
// output: 02
const uint8_t pkt2[] = {0x02, 0x10, 0x22, 0x03};
//An invalid packet (as an STX follows another STX before the
//associated ETX) followed by a valid packet containing 0xFE
// output: fe
const uint8_t pkt3[] = {0x02, 0xFF, 0x02, 0xFE, 0x03};
//A valid packet containing 0xFF and a DLE encoded 0x10,
//followed by a valid packet containing 0xFE
// output:  ff, 10, fe
const uint8_t pkt4[] = {0x02, 0xFF, 0x10, 0x30, 0x03, 0x02, 0xFE, 0x03};
// A valid packet spanning two calls to pkt_decoder_write_bytes()
// output: ff, 02
const uint8_t pkt5[] = {0x02, 0xFF, 0x10};
const uint8_t pkt6[] = {0x22, 0x03};
// invalid packet with improper encoding. no data should be printed
// no output
const uint8_t pkt7[] = {0xFF, 0x45,0x10, 0x03,0x65};

// create a decoder and use it to write decoded packets. Call the destroy and
// print the values and free the struct
pkt_decoder_t* decoder = pkt_decoder_create(pkt_printer, NULL);
pkt_decoder_write_bytes(decoder, sizeof(pkt1), pkt1);
pkt_decoder_write_bytes(decoder, sizeof(pkt2), pkt2);
pkt_decoder_write_bytes(decoder, sizeof(pkt3), pkt3);
pkt_decoder_write_bytes(decoder, sizeof(pkt4), pkt4);
pkt_decoder_write_bytes(decoder, sizeof(pkt5), pkt5);
pkt_decoder_write_bytes(decoder, sizeof(pkt6), pkt6);
pkt_decoder_write_bytes(decoder, sizeof(pkt7), pkt7);
pkt_decoder_destroy(decoder);
return 0;
}
