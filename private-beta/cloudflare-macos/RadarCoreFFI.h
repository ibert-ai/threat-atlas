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

// Live SOC session: GreyNoise public threat-map feed (shared with the screensaver core) plus Radar.
// Creating a session opens the GreyNoise WebSocket; dropping it lets the feed thread stop.
void *ta_soc_new(void);
int32_t ta_soc_set_radar(void *session, const uint8_t *body, size_t len, uint64_t received_ms);
// severities: bit 0 malicious, bit 1 suspicious, bit 2 benign. motion: 0 calm, 1 still.
void ta_soc_set_options(void *session, uint32_t severities, uint32_t motion);
// Frame coordinates (1440x900). Same country or open water clears focus. Returns index or -1.
int32_t ta_soc_focus_at(void *session, float x, float y);
// JSON country details into out; returns byte length or 0.
size_t ta_soc_inspect(void *session, float x, float y, uint8_t *out, size_t capacity);
const uint8_t *ta_soc_frame(void *session);
void ta_soc_drop(void *session);
