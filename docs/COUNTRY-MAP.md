# Country borders and observation shading

Borders use bundled Natural Earth 1:110m admin-0 polygons, with upstream revision
and attribution in assets/ATTRIBUTION.md. Geometry is parsed once, with compound
paths preserving holes and separate islands. Small territories can be absent at
this scale. Borders are a cartographic reference, not an assertion about disputes.

Both source and destination countries of valid recent feed records are shaded.
Feed country name / ISO aliases determine the country; unknown names are ignored,
not guessed from an event coordinate. Source/destination country labels are
provider assertions. Colours reuse exactly the live-feed classification mapping:
malicious red, suspicious orange, benign green; unknown classifications stay
neutral. If multiple classes are active in a country, malicious takes precedence
over suspicious, then benign. Each record expires six seconds after receipt;
when the most severe expires, the next still-active category becomes visible.
Country shading uses every retained recent record, independently of sampled
animated routes. No simulated observations are introduced.

Country paths and the last category overlay are cached, not recreated per frame.
The overlay changes only when the active country/category vector changes.
Acceptance still requires visual review on Windows/macOS, readability under
load, and performance measurement on representative hardware. Wishlist items
remain open until those results and user approval are recorded.
