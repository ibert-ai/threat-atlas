# Threat Atlas – marknadsmaterial

Infört 2026-11-18 av Seek Norris på uppdrag av Robert, efter inventeringen i
`Ibert-Iam/project-status-dashboard` (`marketing/threat-atlas/seek-material-inventory-20261118.md`).

## Varför

Materialet låg tidigare i arbetsytans rot och i `instagram-posts/` och
`preview/`, utanför Git. Det gick alltså inte att svara på vilken version av
produkten en bild visade, vem som gjort den, eller om den var godkänd.

Här är det spårbart.

## Regler

1. **Vektorn i `ibert-se/site-assets` är källan** för logotypen. Rasterfiler
   härleds ur den och redigeras aldrig för hand.
2. **En godkänd symbol.** `ta-globe.svg` gäller. `threat-atlas-symbol.svg` är
   markerad som utfasad i `APPROVALS.md` men ligger kvar tills någon med
   designansvar bekräftat – att radera på egen hand vore att fatta det beslutet
   åt dem.
3. **Nya bilder läggs här, inte i arbetsytan.** Varje fil får en rad i
   `SOURCES.md` med ursprung och, när det finns, godkännande.
4. **GreyNoise-data får inte antyda samarbete.** Se `assets/ATTRIBUTION.md`.

## Innehåll

| Katalog | Vad |
| --- | --- |
| `assets/` | 22 bilder: Instagram-inlägg, produktbilder, delningsbild, profilbild, tysk i18n-sheet |
| `assets/threat-atlas-logo-light.png` | Ny, vit variant för mörk bakgrund, genererad ur den mörka |

Attribution för typsnitt, kartdata och telemetri finns i
`assets/ATTRIBUTION.md` och ändras inte här.
