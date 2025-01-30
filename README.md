# NetGuard
Network Performance Monitoring and Anomaly Detection System.

## Network Performance Monitoring: 
Simple and effective tool for measuring ISP performance at home. The tool measures several performance metrics including packet loss, latency, jitter, and DNS performance. It also has an optional speed test to measure bandwidth. Netprobe aggregates these metrics into a common score, which you can use to monitor overall health of your internet connection.

## Anomaly Detection
Later,The system employs machine learning models such as DTC classifier, KNN Classifier, Logistic Regression Classifier to analyze the lively collected packet-level data and detect anomalies,intrusion detections. Once an anomaly is detected, NetGuard generates an Notification alert. 

## Features : 

1. Network Performance Monitoring (With Defined Metrics using Grafana Dashboard)
2. Packet Analyzer
 - Start Packet Sniffing 
 - Detect Anomalies 
3. Anomalies 
 - Display Binary Classification (Realtime test packet data)
4. Alert Notification
5. Report Generation ( Not implemented yet) 

## Requirements and Setup

To run NetGuard, you'll need a PC running Docker connected directly to your ISP router. Specifically:

NetGuard should be installed on a machine (the 'probe') which has a wired Ethernet connection to your primary ISP router. This ensures the tests are accurately measuring your ISP performance and excluding and interference from your home network. An old PC with Linux installed is a great option for this.

## Installation

### First-time Install

1. Clone the repo locally to the probe machine:

```
https://github.com/galib-1206/NetGuard.git
```

2. From the cloned folder, use docker compose to launch the app:

```
sudo docker-compose up -d
```

3. To shut down the app, use docker compose again:

```
sudo docker-compose down
```
4. For Running NextJS Frontend
```
npm run dev
```
## How to use

1. Navigate to: http://x.x.x.x:3001/d/app/netprobe where x.x.x.x = IP of the probe machine running Docker.

2. Default user / pass is 'admin/admin'. Login to Grafana and set a custom password.

## **Important

1. By Docker Composing up, Network Performance Monitoring will be realtime dashboard.
2. But Frontend & Anomaly Detector Backend is not docker composed. Just run the frontend locally.And from there Backend Python script will be run.
 
## How to customize

### Enable Speedtest

By default the speed test feature is disabled as many users pay for bandwidth usage (e.g. cellular connections). To enable it, edit the .env file to set the option to 'True':

```
SPEEDTEST_ENABLED="True"
```

Note: speedtest.net has a limit on how frequently you can connection and run the test. If you set the test to run too frequently, you will receive errors. Recommend leaving the 'SPEEEDTEST_INTERVAL' unchanged.






