#ifndef PKT_DECODER_H_INCLUDED
#define PKT_DECODER_H_INCLUDED
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

// A macro for maximum lenght of decoded data
// data_length must be <= MAX_DECODED_DATA_LENGTH
#define MAX_DECODED_DATA_LENGTH (512)

// A function pointer for callback function
typedef void (*pkt_read_fn_t)(void *ctx, size_t data_length, const uint8_t *data);

// A structure to store all the required information about the
// decoded data.
typedef struct pkt_decoder
{
  // function pointer
  pkt_read_fn_t funcallback;
  // to store the decoded packet data
  uint8_t pkt_data[MAX_DECODED_DATA_LENGTH];
  // length of the decoded data
  size_t length;
  // Set to true for when STX is first seen
  bool stx_seen;
  // this index is set when another STX is seen after an ETX
  size_t cur_stx_index;
  // Set to true when packets are improperly encoded or
  // when the data length > MAX_DECODED_DATA_LENGTH
  bool invalid;
  // Set to true when ETX is seen in a valid packet case
  bool complete;
} pkt_decoder_t;

// Constructor for a pkt_decoder
pkt_decoder_t* pkt_decoder_create(pkt_read_fn_t callback, void *callback_ctx);

// Destructor for a pkt_decoder
void pkt_decoder_destroy(pkt_decoder_t *decoder);

// Called on incoming, undecoded bytes to be translated into packets
void pkt_decoder_write_bytes(pkt_decoder_t *decoder, size_t len, const uint8_t *data);

#ifdef __cplusplus
}
#endif
#endif //PKT_DECODER_H_INCLUDED
