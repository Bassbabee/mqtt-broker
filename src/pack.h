#ifndef PACK_H
#define PACK_H

#include <stdio.h>
#include <stdint.h>

/* BEGIN READ DATA */
// bytes -> uint8_t
uint8_t unpack_u8(const uint8_t **buf);
// butes -> uint16_t
uint16_t unpack_u16(const uint8_t **buf);
// butes -> uint32_t
uint32_t unpack_u32(const uint8_t **buf);
// get length of bytes
uint8_t *unpack_bytes(const uint8_t **buff, size_t len, uint8_t *str);
// get a string prefix by its length
uint16_t unpack_string16(uint8_t **buf, uint8_t **dest);
/* END READ DATA */

/* BEGIN WRITE DATA */
// append uint8_t into bytestring
void pack_u8(uint8_t **buf, uint8_t val);
// append uint16_t into bytestring
void pack_u16(uint8_t **buf, uint16_t val);
// append uint32_t into bytestring
void pack_u32(uint8_t **buf, uint32_t val);
// append length bytes into bytestring
void pack_bytes(uint8_t **buf, uint8_t *str);
/* END WRITE DATA */

#endif