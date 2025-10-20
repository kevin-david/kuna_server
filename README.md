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

Async Kuna Camera RTSP server: V:1.0.0

positional arguments:
  username              username (default: None))
  password              password (default: None))

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  base RTSP server port to listen on (default: 4554)
  -L LOG, --log LOG     log file name (default: ./KUNA.log)
  -D, --debug           Debug mode (default: False))
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
2025-10-20 17:52:13,903  INFO Main       main                 ./kuna_server.py Version: 1.0.0
2025-10-20 17:52:13,903  INFO Main       main                 Python Version: 3.12.3 (main, Aug 14 2025, 17:47:21) [GCC 13.3.0]
2025-10-20 17:52:13,903 WARNI KUNA       load_token           token.json not found.
2025-10-20 17:52:13,904  INFO KUNA       _request             POST https://server.kunasystems.com/api/v1/account/auth/
2025-10-20 17:52:14,078  INFO KUNA       get_token            got new token: 1567xxxxxxxxxxxxxxxxxxxxxxx18d4c4
2025-10-20 17:52:14,078  INFO KUNA       save_token           token saved
2025-10-20 17:52:14,078  INFO KUNA       _request             GET https://server.kunasystems.com/api/v1/user/cameras/
2025-10-20 17:52:14,277  INFO KUNA       start_rtsp_servers   rtsp server starting
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   Client: start listening for camera: OOKNBL008081601751 (Garden) on 0.0.0.0:4554
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   rtsp server starting
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   Client: start listening for camera: OOKNBL005401503119 (Porch) on 0.0.0.0:4555
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   rtsp server starting
2025-10-20 17:52:14,278  INFO KUNA       start_rtsp_servers   Client: start listening for camera: OOKNBL005401500553 (Driveway) on 0.0.0.0:4556
```

Now open an rtsp client using the local ip address and the port indicated for the camera you want to view using `stream2` (`stream1` works as well).  
eg, for VLC, open "Media"->"Open Network Stream" with the address `rtsp://192.168.100.191:4555/stream2` to connect to camera (Porch) as shown above, if your server is running on local ip address `192.168.100.191`.
VLC will open a UDP connection by default. You can open multiple viewers on each camera using the same connection, but you will overload the camera if you try more than two (I think there is a limit of two connections anyway).  

**NOTE:** You can change the base port number using the `-p` command line option if you have a conflict, the default is `4554`.

## got2rtc

If you are using go2rtc, you may need to experiment, the TCP rtsp stream is a bit unreliable (it buffers quite a bit). I have tried the folowing config (substitute your own ip and ports):
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
