/* Threat Atlas core: screensaver host interface (SP1 session + SP3 worker). Plain C, UTF-8, NUL-terminated strings.
 *
 * Order: ta_saver_new -> ta_saver_worker_start -> loop { ta_saver_fit on size change; about 1/s
 * ta_saver_set_intel(session, ta_saver_worker_osint(worker)); ta_saver_frame; about 1/10 s ta_saver_worker_reload }
 * -> ta_saver_worker_stop -> ta_saver_drop.
 * Every call for one session and its worker must come from ONE thread and never overlap.
 * The frame pointer is invalidated by the next ta_saver_frame, ta_saver_fit_window, ta_saver_fit or ta_saver_drop
 * (a resize reallocates the buffer): copy it out first.
 * The saver only READS AtlasSOC's settings.json. A missing or broken file means every source is off. */
#ifndef THREAT_ATLAS_SAVER_H
#define THREAT_ATLAS_SAVER_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct TaSaverSession TaSaverSession;
typedef struct TaSaverWorker TaSaverWorker;
typedef struct TaOsintHandle TaOsintHandle;

/* Looks one API key up in the system credential store. Write the key (no NUL) into out (capacity cap) and return
 * its length, or 0 for no key. id is a source id such as "abuseipdb". Never log the value.
 * The core clears its own scratch buffer after each call, but the keys it resolves stay in the worker's memory
 * (never on disk) until ta_saver_worker_stop. */
typedef size_t (*TaKeyFn)(const char *id, uint8_t *out, size_t cap, void *user);

TaSaverSession *ta_saver_new(void);
/* Lay the frame out for a window of width x height physical pixels; returns the frame width (height is always
 * 900). Use this one. */
uint32_t ta_saver_fit_window(TaSaverSession *session, uint32_t width, uint32_t height);
/* Sets the frame width directly (1440..4320). Not a window width: prefer ta_saver_fit_window. */
uint32_t ta_saver_fit(TaSaverSession *session, uint32_t frame_width);
void ta_saver_set_intel(TaSaverSession *session, TaOsintHandle *osint);
const uint8_t *ta_saver_frame(TaSaverSession *session); /* RGBA, width*900*4 bytes; NULL on failure */
void ta_saver_drop(TaSaverSession *session);

/* Starts with everything OFF, then reads settings_path once. key_fn may be NULL. Returns NULL on bad input. */
TaSaverWorker *ta_saver_worker_start(const char *data_dir, const char *settings_path, TaKeyFn key_fn, void *user);
void ta_saver_worker_reload(TaSaverWorker *worker); /* cheap when nothing changed */
TaOsintHandle *ta_saver_worker_osint(TaSaverWorker *worker); /* borrowed; valid until stop */
void ta_saver_worker_stop(TaSaverWorker *worker);

#ifdef __cplusplus
}
#endif
#endif
