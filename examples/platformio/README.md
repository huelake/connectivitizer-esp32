# PlatformIO project

The web server of the Arduino examples (`GET /state`, `POST /led`) as a PlatformIO project. Wi-Fi, keys and the choice between relay only and peer to peer are in one file that is not committed.

1. Copy `include/secrets.example.h` to `include/secrets.h` and fill it in.
2. Build, flash and watch the serial output (in this folder):

   ```powershell
   pio run -e esp32dev -t upload -t monitor
   ```

   Environments: `esp32dev` (ESP32), `esp32-s3`, `esp32-c3`, `esp32-s2`. Add `--upload-port COM3 --monitor-port COM3` when PlatformIO picks the wrong port. If `pio` is not on the PATH, it is `$env:USERPROFILE\.platformio\penv\Scripts\pio.exe`, or use the PlatformIO terminal of VS Code.

A board that does not start flashing by itself: hold its BOOT button while PlatformIO prints `Connecting....`.

What the serial monitor shows when it works:

```
Wi-Fi.... connected, address 192.168.1.57
Reachable through Connectivitizer.
```

The device then appears under *Devices* in the web app, online, with the service `api`.

When an app connects, the monitor shows which addresses both sides offered and how they reached each other, for example a phone on mobile data over IPv6:

```
session …: offering "udp":["192.168.1.57:54251","[2001:db8:1:…]:54251","203.0.113.7:54251"],"nat":"cone"}
session …: the app offers "udp":["[2001:db8:2:…]:51234","198.51.100.24:17967"],"nat":"symmetric"}
session … established with Example app (direct, shared-key, app at [2001:db8:2:…]:51234, announced)
```

IPv6 addresses appear some time after the board joins the Wi-Fi, once the router has announced them; sessions before that offer IPv4 only. `learned` instead of `announced` means the app was reached at an address it could not announce itself. A relayed session prints why; [the troubleshooting guide](https://connectivitizer.com/guides/troubleshooting.md) explains the lines.

## In your own project

Replace the `lib_deps` line of `platformio.ini` with `lib_deps = huelakesoftwaresolutions/Connectivitizer` (the library from the PlatformIO registry). Nothing else has to be installed.
