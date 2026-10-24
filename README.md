# Laura — Cloud-Free Oura Ring Gen 3 Household & Couple Hub

**Laura** is a self-hosted web & iOS Progressive Web App (PWA) for individuals and couples with **Oura Ring Gen 3** rings. Built on top of the open-source [`Th0rgal/open_oura`](https://github.com/Th0rgal/open_oura) and [`Th0rgal/open_health`](https://github.com/Th0rgal/open_health) protocol and `ecore` biometric algorithms, Laura operates **100% cloud-free without an Oura Membership or Oura Cloud API**.

It can be hosted for free as a serverless static PWA on **GitHub Pages (`*.github.io`)** or run locally on your own home server with Node.js + SQLite.

---

## ✨ Key Features

- **100% Cloud-Free & Membership-Free (`open_oura` BLE Engine)**:
  - Talks directly to Oura Ring Gen 3 over Bluetooth Low Energy (`98ed0001-a541-11e4-b6a0-0002a5d5c51b`).
  - Authenticates locally via `AES-128-ECB / PKCS#7` challenge-response (`0x2f 0x01 0x2b` → `0x2f 0x11 0x2d`).
  - Decodes raw binary ring history events (`0x41..0x8b`: `bedtime_period`, `sleep_phase_data`, `sleep_period_information_2`, `hrv_event`, `ibi_and_amplitude_event`, `sleep_temp_event`, `spo2_event`, `activity_information`) and computes Readiness, Sleep, and Activity scores locally via `ecore`.
- **Mobile-First iOS PWA & Desktop Web Dashboard**:
  - Installs onto iPhone Home Screens (*Safari → Share → Add to Home Screen*) with a full-screen standalone UI and bottom tab navigation.
- **Multi-Ring & Couple Recovery Sync (Up to 3 Household Users)**:
  - Separate password-protected household profiles with instant ring switching.
  - **Couple Sync View**: Side-by-side Readiness, Sleep, Activity, Resting HR & HRV vs. each person's 30-day rolling baseline, **Bedtime & Sleep Schedule Overlap** timeline, shared recovery streaks, cycle phase awareness, and a 14-day dual trajectory overlay.
- **🌸 Menstrual Cycle Tracking & Oura-Style Cycle Insights**:
  - Uses Oura Ring Gen 3's `0x75 sleep_temp_event` (`±0.01 °C` NTC temperature sensor) to plot the **60-day biphasic nightly skin temperature deviation curve** (cooler Follicular phase below `0.0 °C` vs. warmer progesterone-driven Luteal phase `+0.20 °C` to `+0.45 °C`).
  - Automatic **3-over-6 biphasic thermal shift ovulation detection**, next period countdown, fertile window estimation, 28-day circular phase dial (**Menstrual**, **Follicular**, **Ovulation**, **Luteal**), Follicular vs. Luteal biometric comparison (`Temp Δ`, `Resting HR`, `Nighttime HRV`), and 1-click period flow, LH strip, & symptom logging.
- **Deep Biometric Analytics**:
  - Readiness, Sleep, and Activity circular gauges with contributor breakdowns.
  - Lowest Resting Heart Rate, Nighttime HRV (rMSSD), Body Temperature Deviation (°C), Blood Oxygen (SpO2 %), Daytime Stress vs. Recovery minutes, and Respiratory Rate.
  - **5-Minute Sleep Stage Hypnogram** (Awake, REM, Light, Deep) + Nighttime HR & HRV curves + **24-Hour Intraday Heart Rate**.
  - **Lifestyle Tag Impact Analyzer** & **Pearson $r$ Scatter Correlation Explorer**.
- **Built-In Security Layers**:
  - Strict login gate (unauthenticated by default; all dashboard and ring endpoints require an active cryptographic session token).
  - **OWASP-compliant password hashing**: `PBKDF2-HMAC-SHA256` (210,000 iterations + 16-byte CSPRNG salt) in GitHub Pages browser mode and `scrypt` (`N=16384, r=8, p=1` + 16-byte salt) in Node server mode, verified using constant-time byte comparison.
  - `AES-256-GCM` encryption at rest for 16-byte ring authentication keys.
  - Brute-force login lockout (5 failed attempts → 5-minute cooldown) + admin-locked registration capped at 3 household users.

---

## 📡 How to Connect Your Oura Ring Gen 3 (Step-by-Step)

Because Laura communicates directly with your ring over Bluetooth LE without Oura's cloud servers, you perform a one-time hardware factory reset on the charging dock to replace Oura's cloud key with your own 16-byte key.

### Step 0 (Optional): Export Existing History Before Resetting
If you have older history in your Oura account that you want to keep before wiping the ring:
1. Download your data export (`.csv` or `.json`) from [membership.ouraring.com](https://membership.ouraring.com).
2. In Laura, open **Settings → 📥 Import CSV / JSON Archive** and upload your files.

### Step 1: Unpair the Ring from Your Phone's Bluetooth
An Oura Ring 3 only accepts **one** active Bluetooth LE connection at a time.
1. Force-close (or uninstall) the official **Oura** app on your phone so it does not grab the ring in the background.
2. Open **iOS Settings → Bluetooth**, tap the **`(i)`** icon next to your **Oura Ring**, and tap **Forget This Device**.

### Step 2: Hardware Factory-Reset on the Charging Dock (4-Flip Sequence)
This hardware sequence (documented in [`Th0rgal/open_oura`](https://github.com/Th0rgal/open_oura/blob/main/docs/factory-reset.md)) clears Oura's factory key so your ring accepts a self-generated 16-byte key:
1. Place your Oura Ring 3 on its **powered charging dock** and wait for the LED to illuminate.
2. Keeping the ring seated on the dock, **flip the charger + ring upside-down, then right-side-up 4 times in a row** (~1 flip per second), then place the dock flat on your desk.
3. Wait ~5 seconds — the charger LED will cycle colors, confirming the factory reset is complete.

### Step 3: Pair & Sync Your Ring Over Bluetooth (`Settings` Tab)
> **Browser Compatibility for WebBluetooth (`navigator.bluetooth`)**:
> - **Mac / Windows / Linux / Android**: Open the app in **Google Chrome, Brave, Edge, or Arc** *(desktop Safari does not support WebBluetooth)*.
> - **iPhone / iPad**: Open the app inside the free **[Bluefy – Web BLE Browser](https://apps.apple.com/us/app/bluefy-web-ble-browser/id1492822055)** from the iOS App Store, or sync via Chrome on your Mac.

1. Sign in to Laura and open the **Settings** tab (**`📡 Cloud-Free Oura Ring 3 Hub`**).
2. Under **Step 1: 16-Byte Ring Auth Key & Serial**:
   - Click **`🎲 Generate New 16-Byte Key`** to generate and save a random 32-character hex key to your profile.
3. Under **Step 2: Direct Bluetooth (BLE) Ring Sync & Pairing** (while your factory-reset ring is on the charging dock):
   - Click **`🔑 Pair Factory-Reset Ring (Write 0x24 Key)`**.
   - Select your **Oura Ring** in the browser's Bluetooth dialog and click **Pair**.
   - Laura will write your 16-byte key (`0x24`) to the ring, authenticate via `AES-128-ECB` (`0x2c → 0x2d`), sync the ring's internal clock (`0x12`), enable **Automatic Daytime HR, Workout HR, SpO2, and Resting HR** (`0x26`), trigger on-ring sleep analysis (`0x42`), and drain your binary history packets (`0x41..0x8b`).

### Step 4: Daily Syncing & Adding a Second Ring
- **Daily Sync**: Once paired, your ring is permanently bound to your 16-byte key. Anytime you want to pull new data, open **Settings** and click **`🔵 Connect & Sync Ring via Bluetooth (BLE)`** (or import an `oura.db` SQLite file from the `open_oura` CLI / `open_health` app).
- **Partner's Ring**: Sign in under the second household profile in **Settings** and repeat Steps 1–3 for your partner's ring.

---

## 🔐 Managing Household Logins & Passwords (2–3 Users Max)

1. On first launch, sign in using the initial bootstrap credentials (`alex` / `laura2026`).
2. Go to **Settings → 🛡️ Security Layers & Household Admin → 👥 Household Member Credentials**.
3. Update the usernames, display names, and passwords (8+ characters) for your household members. Once updated, the first-time bootstrap notice on the login page disappears automatically.

---

## 🚀 Deployment Options

### Option A: GitHub Pages (`*.github.io`) — Serverless Static PWA
1. Push this repository to GitHub.
2. In your GitHub repository, go to **Settings → Pages → Build and deployment** and set **Source** to **GitHub Actions**.
3. The included workflow ([`.github/workflows/deploy-pages.yml`](./.github/workflows/deploy-pages.yml)) automatically deploys `./public` to `https://<your-username>.github.io/<repo-name>/`.

### Option B: Self-Hosted Node.js + SQLite Server
Requires Node.js `v22.5+` or `v24+` (uses built-in `node:sqlite`, `node:crypto`, and `node:http` with zero external `npm` dependencies):

```bash
./scripts/run-node.sh src/server.mjs
```

Open **`http://localhost:3000`** in your browser.

### Option C: Docker Compose
```bash
cp .env.example .env
docker compose up -d --build
```
