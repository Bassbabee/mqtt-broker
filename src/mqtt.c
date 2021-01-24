#include <stdlib.h>
#include <string.h>
#include "mqtt.h"

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