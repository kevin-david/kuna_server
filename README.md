# kuna_server
An RSTP server that allows live video connections to Kuna Cameras

## Requirements

Python >= 3.10
uses:
* websockets (pip install websockets)
* aiohttp (pip install aiohttp)

## Usage

```bash
nick@MotionPlus:~/Scripts/kuna_server$ ./kuna_server.py -h
usage: kuna_server.py [-h] [-p PORT] [-L LOG] [-D] username password

Async Kuna Camera RTSP server: V:1.0.1

positional arguments:
  username              username (default: None))
  password              password (default: None))

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  base RTSP server port to listen on (default: 4554)
  -L LOG, --log LOG     log file name (default: None)
  -D, --debug           Debug mode (default: False))
  -M, --minlog          Minnimum Logging (default: False))
```

run: 
```bash
./kuna_server.py <login> <password>
```
where `login` and `password` are your Kuna account credentials

This will start a number of local servers - one for each camera you have in your account.
```bash
2025-10-20 17:52:13,902  INFO Main       main                 *******************
2025-10-20 17:52:13,903  INFO Main       main                 * Program Started *
2025-10-20 17:52:13,903  INFO Main       main                 *******************
2025-10-20 17:52:13,903  INFO Main       main                 ./kuna_server.py Version: 1.0.1
2025-10-20 17:52:13,903  INFO Main       main                 Python Version: 3.12.3 (main, Aug 14 2025, 17:47:21) [GCC 13.3.0]
2025-10-20 17:52:13,903 WARNI KUNA       load_token           token.json not found.
2025-10-20 17:52:13,904  INFO KUNA       _request             POST https://server.kunasystems.com/api/v1/account/auth/
2025-10-20 17:52:14,078  INFO KUNA       get_token            got new token: 1567xxxxxxxxxxxxxxxxxxxxxxx18d4c4
2025-10-20 17:52:14,078  INFO KUNA       save_token           token saved
2025-10-20 17:52:14,078  INFO KUNA       _request             GET https://server.kunasystems.com/api/v1/user/cameras/
2025-10-20 17:52:14,277  INFO KUNA       start_rtsp_servers   rtsp server starting
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   Client: start listening for camera: OOKNBL008081601751 (Garden) on 192.168.100.191:4554
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   rtsp server starting
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   Client: start listening for camera: OOKNBL005401503119 (Porch) on 192.168.100.191:4555
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   rtsp server starting
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   Client: start listening for camera: OOKNBL005401500553 (Driveway) on 192.168.100.191:4556
```

Now open an rtsp client using the local ip address and the port indicated for the camera you want to view using `stream2` (`stream1` works as well).  
eg, for VLC, open "Media"->"Open Network Stream" with the address `rtsp://192.168.100.191:4555/stream2` to connect to camera (Porch) as shown above, if your server is running on local ip address `192.168.100.191`.
VLC will open a UDP connection by default. You can open multiple viewers on each camera using the same connection, but you will overload the camera if you try more than two (I think there is a limit of two connections anyway).  

**NOTE:** You can change the base port number using the `-p` command line option if you have a conflict, the default is `4554`.

## got2rtc/Frigate

If you are using go2rtc or Frigate, you may need to experiment, the TCP rtsp stream is a bit unreliable (it buffers quite a bit). I have tried the folowing config (substitute your own ip and ports):
```yaml
Kuna_porch:
  #NOTE: rtsp does work but is unreliable
  #- rtsp://192.168.100.191:4555/stream2
  #this works best
  - ffmpeg:rtsp://192.168.100.191:4555/stream2#video=h264#audio=aac
  #- ffmpeg:rtsp://192.168.100.191:4555/stream2#video=copy#audio=copy
  #- ffmpeg:rtsp://192.168.100.191:4555/stream2#video=copy#audio=copy#input=rtsp/udp
  #- ffmpeg:rtsp://192.168.100.191:4555/stream2#video=h264#audio=aac#input=rtsp/udp
```
But YMMV.

## Issues

Let me know if there are any bugs by posting in issues.

If you like this repo [buy me a coffee](https://paypal.me/NWaterton)


## Development checks

Run the bridge regression tests with synthetic traffic. They do not connect to cameras or the Kuna service.

```bash
uv run --no-project --python 3.12 --with-requirements requirements.txt python -m unittest discover -s tests -v
./build-addon.sh --sync-only
git diff --exit-code -- homeassistant-addon/kuna_server.py homeassistant-addon/requirements.txt
```

If the Kuna session drops or setup times out, the RTSP connection closes. Configure the consumer (for example, Frigate) to reconnect.

The add-on uses generated copies of the root Python source and requirements. Run `./build-addon.sh --sync-only` after edits, or `./build-addon.sh` to sync and build the image. Pull request builds do not publish images.

After deploying, check each camera's frame rate and watch for repeated disconnects. A synthetic replay cannot establish long-term reliability against the Kuna service.

## Live endpoint trial

`scripts/endpoint_trial.py` tests `video.kunasystems.com` on one RTSP listener
while the other cameras retain `server.kunasystems.com`. It uses the existing
Frigate consumer. It checks the deployed source hash and image, saves the source
in the add-on's private data directory, and restarts the bridge to apply the
temporary camera-specific override. The command records frame-rate samples and
aggregated bridge errors, then restores the exact original source and restarts
the bridge. It verifies the camera-to-port mapping after each restart.

The command requires Proxmox guest-agent access through passwordless sudo and
must run on the Frigate host. The add-on restart briefly interrupts all cameras
served by that bridge; the Frigate container remains running. Normal errors,
Ctrl-C, SIGTERM and SIGHUP enter the restore path. Keep the command running until
it reports restoration; it has no separate rollback service for controller loss.

```bash
uv run --no-project python scripts/endpoint_trial.py \
  --vmid 101 --port 4555 --seconds 600 \
  --output /tmp/kuna-endpoint-trial-2026-10-29.json
```

Evidence files contain camera metadata and stay outside Git. A successful
WebSocket upgrade or synthetic test does not establish camera-stream stability;
judge the trial by fresh input and processing rates and errors over its full
measurement window.

### 2026-10-29 result

A ten-minute trial on the basement camera did not restore its stream. After
the 60-second warmup, all 40 distinct Frigate snapshots reported 0 incoming fps.
The video endpoint produced no TLS verification failures for that camera, but
Kuna returned 35 cloud-side connection refusals during the measured window.
The other two cameras retained the server endpoint. Their new connections
encountered 11 TLS failures in total after the shared bridge restart, then
returned to roughly 5 fps. This prevents treating the controls as continuously
healthy throughout the trial.

The original add-on source was restored with SHA-256
`f8c2b9e8b8349d99f6ab0a569f4b002669783d72c76ab8ac8a02d898c72a8b52`.
The image ID and camera-to-port mapping stayed the same. Frigate was not
restarted. Changing the WebSocket hostname alone did not fix the basement
camera's streaming failure.
