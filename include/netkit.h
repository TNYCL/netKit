#ifndef NETKIT_H
#define NETKIT_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI v1. Handles are thread-confined; serialize calls per handle.
 * Status: 0 success, 1 invalid/error, 2 contained panic, 3 limit, 4 unavailable.
 * JSON outputs are owned by netKit; release with netkit_string_free.
 * Input buffers only need to remain valid until the call returns.
 * On error, output pointers are NULL. After status 2, discard the handle.
 */
typedef struct NetkitEngine NetkitEngine;
typedef struct NetkitPacket {
    uint64_t timestamp_ns;
    uint32_t interface_id;
    uint32_t link_type;
    uint32_t original_len;
    const uint8_t *data;
    size_t data_len;
    const char *sensor;
} NetkitPacket;

uint32_t netkit_abi_version(void);
const char *netkit_last_error(void);
int32_t netkit_engine_new(const char *config_json, NetkitEngine **out);
int32_t netkit_engine_ingest(NetkitEngine *handle, const NetkitPacket *packet, char **out);
int32_t netkit_engine_finish(NetkitEngine *handle, char **out);
int32_t netkit_engine_snapshot(NetkitEngine *handle, char **out);
int32_t netkit_decode_message(NetkitEngine *handle, const char *protocol, const uint8_t *data, size_t data_len, char **out);
void netkit_string_free(char *value);
void netkit_engine_free(NetkitEngine *handle);

#ifdef __cplusplus
}
#endif
#endif
