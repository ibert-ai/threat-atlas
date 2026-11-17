# AtlasSOC Desktop: screen sizes and layout rules

Status: design, 15 Nov 2026 (owner request). Not yet implemented; today the frame is a fixed 1440x900 layout
that only grows in width (`wide_dx`).

## Standard

The layout is designed on a **1920x1080 logical canvas** (16:9, "Full HD"). That is the minimum logical size:
every window is at least 1920x1080 logical, and any extra space is added as rows or columns. Everything else is
derived with **one rule**:

1. Scale `k = min(pixel_width / 1920, pixel_height / 1080)`, snapped **down** to the nearest step in
   {0.67, 0.8, 1, 1.33, 1.5, 2, 3, 4} when within 4 %, otherwise used as is. Snapping never goes up, so the
   logical size never drops below 1920x1080.
2. Logical size = pixel size / k. By construction it is at least 1920x1080. Wider than 16:9 (21:9, 32:9) adds
   **columns**; taller than 16:9 (16:10, 5:4, 4:3) adds **rows**. The canvas is never stretched, so circles stay
   round and text stays crisp.
3. Lowest supported scale is `k = 0.67` (1280x720). Windows smaller than that are best effort: they use a compact
   layout (fewer standing panels, the rest rotate) that is not part of the golden tests.
4. The internal render size is capped at about 8.3 million pixels (3840x2160). Above that (8K) the host renders
   at the cap and scales the frame up.

## Sizes that must work (most common first)

Worldwide desktop share per [StatCounter](https://gs.statcounter.com/screen-resolution-stats/desktop/worldwide/)
(June 2026): 1920x1080 about 20 %, 1536x864 about 7 %, 1280x720 about 6 %. 1920x1080 leads in every region.

| Class | Sizes (pixels) | k | Logical size | Note |
|---|---|---|---|---|
| HD / small laptop | 1280x720, 1366x768, 1536x864, 1600x900 | 0.67, 0.71, 0.8, 0.83 | 1920x1080 | text min 10 px after scale |
| Full HD (base) | 1920x1080 | 1 | 1920x1080 | reference layout |
| QHD | 2560x1440 | 1.33 | 1920x1080 | |
| 4K | 3840x2160 | 2 | 1920x1080 | native render |
| 8K | 7680x4320 | 4 | 1920x1080 | rendered at the pixel cap, scaled up by the host |
| 16:10 | 1440x900, 1680x1050, 1920x1200, 2560x1600, 2880x1800 | 0.75, 0.88, 1, 1.33, 1.5 | 1920x1200 | extra rows |
| 5:4 and 4:3 | 1280x1024, 1600x1200, 1920x1440 | 0.67, 0.83, 1 | 1920x1536, 1920x1440, 1920x1440 | extra rows |
| Ultrawide 21:9 and 24:10 | 2560x1080, 3440x1440, 3840x1600, 5120x2160 | 1, 1.33, 1.48, 2 | 2560x1080, 2580x1080, 2592x1080, 2560x1080 | extra columns |
| Super-ultrawide 32:9 | 5120x1440 | 1.33 | 3840x1080 | extra columns |
| Two 4K screens spanned | 7680x2160 | 2 | 3840x1080 | extra columns, see Multiple screens |
| Below the minimum | 1024x768 | 0.67 (clamped) | compact layout | best effort, not golden-tested |

## Placement of intel parts (the standard)

Panels are placed by **slot order**, never by source, so a source that is switched off simply leaves no gap.

1. Fixed: header tiles, map, received-records strip, latest records, Radar rows.
2. Standing panels, filled in this order while space remains: most attacked ports (SANS ISC), known exploited
   (KEV + EPSS), ransomware, AlienVault OTX pulses, abuse.ch URLhaus, abuse.ch ThreatFox, Tor exits, SSLBL,
   Spamhaus, phishing list, certificate watch (only when the user has entered domains).
3. Anything that does not fit rotates in the last standing slot every 8 s (as the cards do today).
4. Extra width adds standing slots on the right; extra height adds slots below the map.
5. **Click-only sources are dialogs, not slots:** Shodan InternetDB and AbuseIPDB never take a standing slot,
   and a keyed source without its key takes no slot either.

## Acceptance

- Golden-image tests at 1280x720, 1920x1080, 2560x1440, 3840x2160, 1920x1200, 1280x1024, 1920x1440, 3440x1440,
  3840x1600, 5120x1440 and a 7680x2160 span; the logical size column above is what each test asserts.
- No text below 10 px after scaling; no overlap at any listed size; turning a source off never leaves a gap.
- 8K, 5120x1440 and 7680x2160 checked for frame time (budget: under 33 ms on the reference PC).
- 1024x768 is checked only for "usable, no crash"; no golden image.

## Multiple screens (to do, owner request 15 Nov 2026)

The Desktop app must handle two or more screens as an option, the way the screensaver version does
(see the screensaver's multi-monitor modes in README.md and the earlier graphics-test notes).

- Setting in Settings: one screen (default), span all screens as one canvas, or one panel set per screen.
- Each screen is sized by the rules above on its own; a spanned canvas counts as one wide frame (32:9 rules).
- Remember the choice and the screen per window; recover when a screen is unplugged.
- Test on the multi-monitor PC listed in the project notes before the stable release, including hot-plug and
  mixed DPI (for example 100 % on one screen and 150 % on the other): each screen keeps its own `k`.
