# Route Chain

A small app to generate a long path in traceroute.

## Usage

Run `make` to compile the app.

Optionally run `make install` to copy the app to `/usr/local/bin`.

Run `./route-chain 192.168.0.1/24 192.0.0.1/24 fc00::/64 fd00::/64`.

Any number of CIDRs is accepted as parameter.

Then run `traceroute 192.0.0.10` (or any address in the CIDRs above), and you will get:

```bash
traceroute to 192.0.0.10 (192.0.0.10), 30 hops max, 60 byte packets
 1  192.0.0.2  0.105 ms  0.048 ms  0.039 ms
 2  192.0.0.3  0.037 ms  0.036 ms  0.037 ms
 3  192.0.0.4  0.036 ms  0.039 ms  0.039 ms
 4  192.0.0.5  0.043 ms  0.037 ms  0.037 ms
 5  192.0.0.6  0.036 ms  0.038 ms  0.049 ms
 6  192.0.0.7  0.036 ms  0.060 ms  0.042 ms
 7  192.0.0.8  0.038 ms  0.052 ms  0.041 ms
 8  192.0.0.9  0.036 ms  0.037 ms  0.037 ms
 9  192.0.0.10  0.037 ms  0.037 ms  0.036 ms
```

## Internals

This app is made with speed and efficiency in mind. Specifically:

1. Only 2 memory copies per packet:
   - One necessary copy from TUN device to app's memory region (for receiving)
   - All packet processing happen without extra copies
   - One necessary copy from app's memory region to TUN device (for sending)
2. Reserved space for IP/ICMP header for response packets
   - Used for responding Destination Unreachable messages
   - No need to move data around
3. Incremental checksum updates where possible
   - Used for responding to Pings, only minimal updates needed
4. And it's multithreaded!
   - CPU count automatically detected, multiqueue TUN/TAP used

## License

Just do whatever you want.
