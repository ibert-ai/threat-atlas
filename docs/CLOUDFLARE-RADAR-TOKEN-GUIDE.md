# Add Cloudflare Radar to Threat Atlas SOC — step by step

Threat Atlas SOC shows live GreyNoise records without any setup. If you also want
**Cloudflare Radar** country data on the map, you need your own free Cloudflare API token.
This guide takes about five minutes.

> **Which app?** Cloudflare Radar works in **Threat Atlas SOC for macOS**. The Windows
> version shows GreyNoise data only and does not use a Cloudflare token yet.

## What you need

- A Cloudflare account. A free account is enough: sign up at <https://dash.cloudflare.com/sign-up>.
- Threat Atlas SOC for macOS, opened once, with the licence notice accepted.

## Part 1 — Create your token in Cloudflare

1. Sign in at <https://dash.cloudflare.com>.
2. Open **My Profile** (the person icon, top right) and choose **API Tokens**.
   Direct link: <https://dash.cloudflare.com/profile/api-tokens>
3. Click **Create Token**.
4. **Token name:** type something you will recognise later, for example `Threat Atlas SOC`.
5. Under **Policies**, click **Start from scratch** (marked *Custom*).
   Do not pick a ready-made template; they give far more access than the app needs.
6. Set the permission to exactly one line:

   | Scope | Item | Access |
   |-------|------|--------|
   | **Account** | **Radar** | **Read** |

   If Cloudflare asks which account, choose your own. Add nothing else.
7. **Token expiration:** pick an end date, for example **90 days** or **1 year**. You can make
   a new token when it runs out.
8. Leave **Client IP address filtering** empty (unless you know you want it).
9. Click through to the summary and create the token.
10. Cloudflare shows the token **only once**. Click the copy button next to it.
    Keep the page open until Part 2 is done.

## Part 2 — Add the token to the app

1. Open **Threat Atlas SOC** on your Mac.
2. Click in the field **Cloudflare API token · Account / Radar / Read** near the top.
3. Paste the token (**⌘V**). It shows as dots, which is normal.
4. Click **Save in Keychain**. The app confirms: *Token saved in Keychain. Press Start when ready.*
   The field empties again; the token is now stored in your Mac's Keychain, not in the app.
5. Click **Start**. After a moment Cloudflare Radar data appears: origin markers on the map and
   the **Cloudflare Radar / top rows** panel. The app asks Cloudflare at most once every
   15 minutes.
6. You can now close the Cloudflare page.

**Pause** stops the Radar requests at any time; the GreyNoise live view keeps running.

## Change, replace or remove the token

- **New token:** paste it into the same field and click **Save in Keychain**. It replaces the
  old one.
- **Remove it from your Mac:** open the **Keychain Access** app, search for
  `ThreatAtlas.PrivateRadarBeta`, and delete that item.
- **Cancel it everywhere:** in Cloudflare, go to **My Profile → API Tokens**, open the
  token's menu (**…**) and choose **Delete** (or **Roll** to get a new value).

## If something goes wrong

| What you see | What to do |
|--------------|------------|
| *Enter a valid Radar Read token.* | The field was empty or the paste failed. Copy the token again and paste it. |
| *Fetch or response validation failed.* | Usually the permission is wrong or the token has expired. Check that the token has **Account · Radar · Read** only and is still active in Cloudflare, then save a new one. |
| Data shows **STALE** | The last Radar answer is older than 30 minutes, for example while offline. It updates by itself on the next successful request. |
| No Radar panel data after Start | Wait one minute; check that your Mac is online and that **Start** is not greyed out (it is greyed out while already running). |

## Good to know

- **Your token stays yours.** It is stored only in your Mac's Keychain. Threat Atlas never
  sends it anywhere except to Cloudflare (`api.cloudflare.com`), over verified HTTPS.
- **Never share the token** in email, chat, screenshots or support requests. Ibert Consulting
  will never ask you for it. If you think it was exposed, delete it in Cloudflare and create a
  new one.
- **Data licence:** Cloudflare Radar data is licensed CC BY-NC 4.0 (attribution, non-commercial).
  Commercial use needs separate permission from Cloudflare. The app shows these terms on first
  launch.
- **What Radar shows:** past-day aggregate shares by country, not individual attacks and not
  attacks on your own systems.
