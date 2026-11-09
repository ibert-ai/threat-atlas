# Add Cloudflare Radar to Threat Atlas SOC — step by step

Threat Atlas SOC shows live GreyNoise records without any setup. If you also want
**Cloudflare Radar** country data on the map, you need your own free Cloudflare API token.
This guide takes about five minutes.

This guide also ships with the app: on a Mac click **How to get a token…** next to the token
field; on Windows right-click the map and choose **How to get a token...**.

> **Which app?** Cloudflare Radar works in **Threat Atlas SOC (AtlasSOC) for macOS and
> Windows**. Linux is not included yet.

## What you need

- A Cloudflare account. A free account is enough: sign up at <https://dash.cloudflare.com/sign-up>.
- Threat Atlas SOC for macOS or Windows, opened once, with the licence notice accepted.

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

### On a Mac

1. Open **Threat Atlas SOC** on your Mac.
2. Click in the field **Cloudflare API token · Account / Radar / Read** near the top.
3. Paste the token (**⌘V**). It shows as dots, which is normal.
4. Click **Save in Keychain**. The app confirms: *Token saved in Keychain. Press Start when ready.*
   The field empties again; the token is now stored in your Mac's Keychain, not in the app.
5. Click **Start**. After a moment Cloudflare Radar data appears: origin markers on the map and
   the **Cloudflare Radar / top rows** panel. The app asks Cloudflare at most once every
   15 minutes.
6. You can now close the Cloudflare page.

Once Cloudflare has accepted the token, the setup area disappears and everything sits in one
row above the map. **Pause Radar** stops the requests at any time; the GreyNoise live view keeps
running. To change the token later, click **Token…** or choose **AtlasSOC → Cloudflare Token…**
(⌘,).

### On Windows

1. Open **AtlasSOC** on your PC.
2. **Right-click** anywhere on the map and choose **Set Cloudflare token...**.
3. A Windows credential window opens. The user name is already filled in
   (*Cloudflare API token*). Click in the **password** field and paste the token (**Ctrl+V**).
   It shows as dots, which is normal. Click **OK**.
4. AtlasSOC confirms the token is saved in **Windows Credential Manager** and asks whether to
   start Cloudflare Radar now. Click **Yes**.
5. After a moment Cloudflare Radar data appears: origin markers on the map and the
   **Cloudflare Radar / top rows** panel. AtlasSOC asks Cloudflare at most once every
   15 minutes.
6. You can now close the Cloudflare page.

The right-click menu shows the current Radar status on its last line. **Pause Cloudflare
Radar** stops the requests; **Cloudflare layer on map** hides or shows the markers.

## Change, replace or remove the token

- **New token (Mac):** click **Token…**, paste the new token and click **Save in Keychain**.
  It replaces the old one.
- **New token (Windows):** right-click > **Set Cloudflare token...** and paste the new one.
- **Remove it from your Mac:** open the **Keychain Access** app, search for
  `ThreatAtlas.PrivateRadarBeta`, and delete that item.
- **Remove it from Windows:** right-click > **Remove Cloudflare token**, or open **Credential
  Manager → Windows Credentials** and remove `AtlasSOC/CloudflareRadarRead`.
- **Cancel it everywhere:** in Cloudflare, go to **My Profile → API Tokens**, open the
  token's menu (**…**) and choose **Delete** (or **Roll** to get a new value).

## If something goes wrong

| What you see | What to do |
|--------------|------------|
| *Enter a valid Radar Read token.* | The field was empty or the paste failed. Copy the token again and paste it. |
| *Fetch or response validation failed.* / *Network request failed.* | Usually the computer is offline, or the token has expired. Check that the token is still active in Cloudflare, then save a new one if needed. |
| *Authorization denied (401)* or *(403)* | The token is wrong, expired or lacks **Account · Radar · Read**. Create a new token with exactly that permission and save it. |
| Data shows **STALE** | The last Radar answer is older than 30 minutes, for example while offline. It updates by itself on the next successful request. |
| No Radar panel data after Start | Wait one minute and check that the computer is online. The 15-minute limit also applies after a restart, so a new request can take up to 15 minutes. |

## Good to know

- **Your token stays yours.** It is stored only in your Mac's Keychain or in Windows
  Credential Manager for your account. Threat Atlas never sends it anywhere except to
  Cloudflare (`api.cloudflare.com`), over verified HTTPS.
- **Never share the token** in email, chat, screenshots or support requests. Ibert Consulting
  will never ask you for it. If you think it was exposed, delete it in Cloudflare and create a
  new one.
- **Data licence:** Cloudflare Radar data is licensed CC BY-NC 4.0 (attribution, non-commercial).
  Commercial use needs separate permission from Cloudflare. The app shows these terms on first
  launch.
- **What Radar shows:** past-day aggregate shares by country, not individual attacks and not
  attacks on your own systems.
