# Källor för marknadsmaterialet

Varje fil i `assets/` med ursprung och kontrollsumma. SHA-256 kortad till
16 tecken; räcker för att avgöra om två filer är identiska.

Kolumnen **Godkänd** är medvetet "okänd" för allt utom där det finns skriftligt
belägg. Se `Ibert-Iam/project-status-dashboard`, `marketing/threat-atlas/APPROVALS.md`.

## Instagram-inlägg

| Fil | SHA-256 (16) | Ursprung | Godkänd |
| --- | --- | --- | --- |
| `ig-post2.png` | 5c72c362d88d63fc | arbetsytans rot | okänd |
| `ig-post3.png` | 5e19efff122083c4 | arbetsytans rot | okänd |
| `ig-post4-1.png` | 52e1ded7953f6425 | arbetsytans rot | okänd |
| `ig-post4-2.png` | d3ab57d61fb79cee | arbetsytans rot | okänd |
| `ig-post4-3.png` | 66b8d054071eaef1 | arbetsytans rot | okänd |
| `ig-post4-4.png` | 3fa27d6f6ebf7c69 | arbetsytans rot | okänd |
| `ig-post5.png` | 2c177314ce7070fb | arbetsytans rot | okänd |
| `ig-post6.png` | 17ea21db62e00be4 | arbetsytans rot | okänd |
| `ig-post7-folj.png` | 7453c486f9809621 | `instagram-posts/` | okänd |
| `ig-release-047.png` | 6e95eddc5dbd4043 | arbetsytans rot | okänd |
| `release-card.png` | 94d8fb07ff2cd3e0 | `instagram-posts/` | okänd |
| `nyhet-2027.png` | 500af73ffbb0bfd6 | `instagram-posts/` | okänd |
| `threat-atlas-instagram.png` | bdf99aa485bd8457 | arbetsytans rot | okänd |
| `instagram-profil.png` | 8f126a3620fc33ab | arbetsytans rot | okänd |

## Produktbilder

| Fil | SHA-256 (16) | Ursprung | Godkänd |
| --- | --- | --- | --- |
| `threat-atlas-skarmbild.png` | 5c87f588a9b0c2f2 | arbetsytans rot | okänd |
| `seeker-live-window.png` | 7de1ad798b677046 | `preview/` | okänd |
| `seeker-real-1440x900.png` | 59cf6e1f8be550fd | `preview/` | okänd |
| `seeker-theme-1440x900.png` | d4b0b70c159d2078 | `preview/` | okänd |
| `seeker-theme-1920x1200.png` | 8fac8637de9b9f79 | `preview/` | okänd |
| `themes-settings-mockup.png` | 9cd7f16b460a6ff4 | `preview/` | okänd |

## Övrigt

| Fil | SHA-256 (16) | Ursprung | Godkänd |
| --- | --- | --- | --- |
| `og-image.png` | 754ddf1c862cc648 | arbetsytans rot | okänd |
| `threat-atlas-i18n-sheet-de.png` | ebb4b856fd8503f3 | arbetsytans rot | okänd |

## Kända dubbletter

Följande låg både i arbetsytans rot och i `instagram-posts/` med identisk
kontrollsumma. Rotfilen togs med, kopian hoppades över:

`ig-post2`, `ig-post3`, `ig-post4-1`, `ig-post4-2`, `ig-post4-3`, `ig-post4-4`,
`ig-post5`, `ig-post6`.

## Genererad fil

| Fil | Hur | Granskad |
| --- | --- | --- |
| `threat-atlas-logo-light.png` | Vit silhuett ur `assets/threat-atlas-logo-dark.png`, alfakanalen bevarad | ⚠️ nej – genererad av agent, behöver blick av någon med designansvar |

## Vad som inte flyttades

| Material | Varför |
| --- | --- |
| `avatar/` (16 filer) | Porträtt och verktyg för teamkonton, inte produktmarknadsföring |
| `marketing/` i arbetsytan (20 filer) | Agentdrift: minne, scheman, loggar – hör inte i ett produktrepo |
| `ibert-se`-bilder | Ligger redan versionshanterat i rätt repo |
