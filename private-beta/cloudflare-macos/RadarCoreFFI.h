// Shared Rust core (crates/core) entry points for the standalone SOC Radar view.
#include <stddef.h>
#include <stdint.h>

void *ta_radar_new(void);
// 0 when the Cloudflare response body was accepted; -1 when rejected (prior data kept).
int32_t ta_radar_set(void *session, const uint8_t *body, size_t len, uint64_t received_ms);
// RGBA premultiplied, ta_width() x ta_height(); valid until the next frame or ta_radar_drop.
const uint8_t *ta_radar_frame(void *session);
void ta_radar_drop(void *session);
uint32_t ta_width(void);
uint32_t ta_height(void);
