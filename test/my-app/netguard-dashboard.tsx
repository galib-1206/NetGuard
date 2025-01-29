"use client"

import { useState } from "react"
import { Bell, AlertTriangle, FileText, ExternalLink } from "lucide-react"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function NetguardDashboard() {
  const [grafanaUrl, setGrafanaUrl] = useState("http://x.x.x.x:3001/d/app/netprobe")

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-6">Netguard Dashboard</h1>

      <Tabs defaultValue="grafana" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="grafana">Grafana Dashboard</TabsTrigger>
          <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="grafana" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Grafana Performance Dashboard</CardTitle>
              <CardDescription>Live network performance metrics</CardDescription>
            </CardHeader>
            <CardContent className="h-[calc(100vh-300px)] min-h-[500px]">
              <iframe src={grafanaUrl} width="100%" height="100%" frameBorder="0" title="Grafana Dashboard"></iframe>
            </CardContent>
            <CardFooter>
              <Button onClick={() => window.open(grafanaUrl, "_blank")}>
                Open in New Tab
                <ExternalLink className="ml-2 h-4 w-4" />
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="anomalies" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Anomaly Detection</CardTitle>
              <CardDescription>Unusual network behavior</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-amber-500 flex items-center">
                <AlertTriangle className="mr-2" />
                <span>1 anomaly detected</span>
              </div>
              {/* Add more detailed anomaly information here */}
            </CardContent>
            <CardFooter>
              <Button variant="outline">Investigate Anomalies</Button>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Recent Notifications</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li className="flex items-center">
                  <Bell className="mr-2 h-4 w-4" />
                  <span>High latency detected (2 hours ago)</span>
                </li>
                <li className="flex items-center">
                  <Bell className="mr-2 h-4 w-4" />
                  <span>Packet loss spike (1 day ago)</span>
                </li>
              </ul>
            </CardContent>
            <CardFooter>
              <Button variant="outline">View All Notifications</Button>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Generated Reports</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li className="flex items-center">
                  <FileText className="mr-2 h-4 w-4" />
                  <span>Weekly Performance Report</span>
                </li>
                <li className="flex items-center">
                  <FileText className="mr-2 h-4 w-4" />
                  <span>Monthly Intrusion Insights</span>
                </li>
              </ul>
            </CardContent>
            <CardFooter>
              <Button variant="outline">Generate New Report</Button>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

