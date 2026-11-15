# AtlasSOC Desktop: screen sizes and layout rules

Status: design, 15 Nov 2026 (owner request). Not yet implemented; today the frame is a fixed 1440x900 layout
that only grows in width (`wide_dx`).

## Standard

The layout is designed on a **1920x1080 logical canvas** (16:9, "Full HD"). Everything else is derived:

1. Pick the scale `k` from the window/screen height in pixels: `k = pixel_height / 1080`, snapped to the
   nearest step in {0.67, 0.8, 1, 1.33, 1.5, 2, 3, 4} when within 4 %, otherwise used as is.
2. Logical size = pixel size / k. Width beyond 1920 (21:9, 32:9) adds columns; height beyond 1080 (16:10, 4:3)
   adds rows. The canvas is never stretched, so circles stay round and text stays crisp.
3. Internal render size is capped at 3840x2160. Above that (8K) the host scales the 4K frame up 2x.

## Sizes that must work (most common first)

Worldwide desktop share per [StatCounter](https://gs.statcounter.com/screen-resolution-stats/desktop/worldwide/)
(June 2026): 1920x1080 about 20 %, 1536x864 about 7 %, 1280x720 about 6 %. 1920x1080 leads in every region.

| Class | Sizes | k | Note |
|---|---|---|---|
| HD / small laptop | 1280x720, 1366x768, 1536x864, 1600x900 | 0.67 to 0.83 | text min 10 px after scale |
| Full HD (base) | 1920x1080 | 1 | reference layout |
| QHD | 2560x1440 | 1.33 | |
| 4K | 3840x2160 | 2 | native render |
| 8K | 7680x4320 | 4 | rendered at 4K, scaled 2x by the host |
| 16:10 | 1440x900, 1680x1050, 1920x1200, 2560x1600, 2880x1800 | by width | extra rows |
| Ultrawide 21:9 | 2560x1080, 3440x1440, 5120x2160 | by height | extra columns |
| Super-ultrawide 32:9 | 5120x1440 | by height | extra columns |

## Placement of intel parts (the standard)

Panels are placed by **slot order**, never by source, so a source that is switched off simply leaves no gap.

1. Fixed: header tiles, map, received-records strip, latest records, Radar rows.
2. Standing panels, filled in this order while space remains: most attacked ports, known exploited (KEV),
   ransomware, Tor exits, SSLBL, Spamhaus, phishing list.
3. Anything that does not fit rotates in the last standing slot every 8 s (as the cards do today).
4. Extra width adds standing slots on the right; extra height adds slots below the map.

## Acceptance

- Golden-image tests at 1280x720, 1920x1080, 2560x1440, 3840x2160, 1920x1200, 3440x1440, 5120x1440.
- No text below 10 px after scaling; no overlap at any listed size; turning a source off never leaves a gap.
- 8K and 5120x1440 checked for frame time (budget: under 33 ms on the reference PC).
