# NetGuard
Advanced Network Performance Monitoring & Anomaly Detection Tool.

Simple and effective tool for measuring ISP performance at home. The tool measures several performance metrics including packet loss, latency, jitter, and DNS performance. It also has an optional speed test to measure bandwidth. Netprobe aggregates these metrics into a common score, which you can use to monitor overall health of your internet connection.

## Requirements and Setup

To run NetGuard, you'll need a PC running Docker connected directly to your ISP router. Specifically:

## Installation

### First-time Install

1. Clone the repo locally to the probe machine

2. From the cloned folder, use docker compose to launch the app:

```
docker compose up
```

3. To shut down the app, use docker compose again:

```
docker compose down
```

### How to use

1. Navigate to: http://x.x.x.x:3001/d/app/netprobe where x.x.x.x = IP of the probe machine running Docker.

2. Default user / pass is 'admin/admin'. Login to Grafana and set a custom password.


