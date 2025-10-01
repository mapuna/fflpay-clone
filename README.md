# FFplay Clone - Adaptive RTSP Player

An extremely simple RTSP video player with real-time adaptive streaming capabilities by handling network conditions with automatic parameter adjustment.

**It was built as a PoC for a separate larger project that handles millions of streams!**

## Features

**Network Monitoring**

- Real-time network bandwidth measurement
- MTU detection using socket-level probing
- Jitter calculation based on inter-packet timing variations
- Packet loss detection using timing gap analysis
- Network metrics logging

**Adaptive Streaming**

- Dynamic buffer size adjustment based on network conditions
- Reorder queue sizing for packet loss mitigation
- Timeout adaptation based on measured network latency
- TCP transport preference for reliable delivery
- Real-time parameter adjustment every N packets

## Requirements

- CMake 3.21 or higher
- FFMPEG libraries (>= version 6.1)
- SDL2

## Adaptive Parameters

The system automatically adjusts these parameters based on network conditions:

- **Buffer Size**: dynamic sizing based on bandwidth and packet loss
- **Reorder Queue**: 50-70 packets based on loss rate and jitter
- **Timeout**: 10-30 seconds based on measured network latency
- **Transport**: TCP preference for reliable RTSP delivery
