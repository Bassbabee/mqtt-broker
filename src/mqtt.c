#include <stdlib.h>
#include <string.h>
#include "mqtt.h"
#include "pack.h"

static const int MAX_LEN_BYTES = 4;

static size_t unpack_mqtt_connect(const unsigned char *raw, union mqtt_header *hdr, union mqtt_packet *pkt);
static size_t unpack_mqtt_publish(const unsigned char *raw, union mqtt_header *hdr, union mqtt_packet *pkt);
static size_t unpack_mqtt_subscribe(const unsigned char *raw, union mqtt_header *hdr, union mqtt_packet *pkt);
static size_t unpack_mqtt_unsubscribe(const unsigned char *raw, union mqtt_header *hdr, union mqtt_packet *pkt);
static size_t unpack_mqtt_ack(const unsigned char *raw, union mqtt_header *hdr, union mqtt_packet *pkt);
static unsigned char *pack_mqtt_header(const union mqtt_header *hdr);
static unsigned char *pack_mqtt_ack(const union mqtt_packet *pkt);
static unsigned char *pack_mqtt_connack(const union mqtt_packet *pkt);
static unsigned char *pack_mqtt_suback(const union mqtt_packet *pkt);
static unsigned char *pack_mqtt_publish(const union mqtt_packet *pkt);

extern int mqtt_encode_length(unsigned char *buf, size_t len) {
    int bytes = 0;
    do {
        if (bytes + 1 > MAX_LEN_BYTES)
            return bytes;
        short d = len % 128;
        len /= 128;
        if (len > 0)
            d |= 128;
        buf[bytes++] = d;
    } while (len > 0);
    return bytes;
}

extern unsigned long long mqtt_decode_length(const unsigned char **buf){
    char c;
    int multiplier = 1;
    unsigned long long value = 0LL;
    do {
        c = **buf;
        value += (c % 127) * multiplier;
        multiplier *= 128;
        (*buf)++;
    } while ((c & 128) != 0);
    return value;
}

static size_t unpack_mqtt_connect(const unsigned char *raw, union mqtt_header *hdr, union mqtt_packet *pkt){
    struct mqtt_connect connect = { .header = *hdr };
    pkt->connect = connect;
    const unsigned char *init = raw;

    size_t len = mqtt_decode_length(&raw);

    // Ignore first 8th bytes
    raw = init + 8;

    // Get 8 bits for flags 
    pkt->connect.byte = unpack_u8((const uint8_t **) &raw);

    pkt->connect.payload.keepalive = unpack_u16((const uint8_t **) &raw);
    
    uint16_t cid_len = unpack_u16((const uint8_t **) &raw);

    if (cid_len > 0) {
        pkt->connect.payload.client_id = malloc(cid_len + 1);
        unpack_bytes((const uint8_t **) &raw, cid_len, pkt->connect.payload.client_id);
    }

    if (pkt->connect.bits.username == 1)
        unpack_string16(&raw, &pkt->connect.payload.username);
    
    if (pkt->connect.bits.password == 1)
        unpack_string16(&raw, &pkt->connect.payload.password);
    
    return len;
}