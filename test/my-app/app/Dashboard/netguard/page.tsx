// "use client"

// import { useState } from "react"
// import { Bell, AlertTriangle, FileText, ExternalLink } from "lucide-react"
// import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
// import { Button } from "@/components/ui/button"
// import { Progress } from "@/components/ui/progress"
// import { Badge } from "@/components/ui/badge"
// import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// export default function NetguardDashboard() {
//   const [grafanaUrl, setGrafanaUrl] = useState("http://x.x.x.x:3001/d/app/netprobe")

//   return (
//     <div className="container mx-auto p-4">
//       <h1 className="text-3xl font-bold mb-6">Netguard Dashboard</h1>

//       <Tabs defaultValue="grafana" className="w-full">
//         <TabsList className="grid w-full grid-cols-4">
//           <TabsTrigger value="grafana">Grafana Dashboard</TabsTrigger>
//           <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
//           <TabsTrigger value="notifications">Notifications</TabsTrigger>
//           <TabsTrigger value="reports">Reports</TabsTrigger>
//         </TabsList>

//         <TabsContent value="grafana" className="mt-4">
//           <Card>
//             <CardHeader>
//               <CardTitle>Grafana Performance Dashboard</CardTitle>
//               <CardDescription>Live network performance metrics</CardDescription>
//             </CardHeader>
//             <CardContent className="h-[calc(100vh-300px)] min-h-[500px]">
//               <iframe src={"http://127.0.0.1:3001/d/app/netprobe?orgId=1&from=now-30m&to=now&timezone=browser"} width="100%" height="100%" frameBorder="0" title="Grafana Dashboard"></iframe>
//             </CardContent>
//             <CardFooter>
//               <Button onClick={() => window.open("http://127.0.0.1:3001/d/app/netprobe?orgId=1&from=now-30m&to=now&timezone=browser", "_blank")}>
//                 Open in New Tab
//                 <ExternalLink className="ml-2 h-4 w-4" />
//               </Button>
//             </CardFooter>
//           </Card>
//         </TabsContent>

//         <TabsContent value="anomalies" className="mt-4">
//           <Card>
//             <CardHeader>
//               <CardTitle>Anomaly Detection</CardTitle>
//               <CardDescription>Unusual network behavior</CardDescription>
//             </CardHeader>
//             <CardContent>
//               <div className="text-amber-500 flex items-center">
//                 <AlertTriangle className="mr-2" />
//                 <span>1 anomaly detected</span>
//               </div>
//               {/* Add more detailed anomaly information here */}
//             </CardContent>
//             <CardFooter>
//               <Button variant="outline">Investigate Anomalies</Button>
//             </CardFooter>
//           </Card>
//         </TabsContent>

//         <TabsContent value="notifications" className="mt-4">
//           <Card>
//             <CardHeader>
//               <CardTitle>Recent Notifications</CardTitle>
//             </CardHeader>
//             <CardContent>
//               <ul className="space-y-2">
//                 <li className="flex items-center">
//                   <Bell className="mr-2 h-4 w-4" />
//                   <span>High latency detected (2 hours ago)</span>
//                 </li>
//                 <li className="flex items-center">
//                   <Bell className="mr-2 h-4 w-4" />
//                   <span>Packet loss spike (1 day ago)</span>
//                 </li>
//               </ul>
//             </CardContent>
//             <CardFooter>
//               <Button variant="outline">View All Notifications</Button>
//             </CardFooter>
//           </Card>
//         </TabsContent>

//         <TabsContent value="reports" className="mt-4">
//           <Card>
//             <CardHeader>
//               <CardTitle>Generated Reports</CardTitle>
//             </CardHeader>
//             <CardContent>
//               <ul className="space-y-2">
//                 <li className="flex items-center">
//                   <FileText className="mr-2 h-4 w-4" />
//                   <span>Weekly Performance Report</span>
//                 </li>
//                 <li className="flex items-center">
//                   <FileText className="mr-2 h-4 w-4" />
//                   <span>Monthly Intrusion Insights</span>
//                 </li>
//               </ul>
//             </CardContent>
//             <CardFooter>
//               <Button variant="outline">Generate New Report</Button>
//             </CardFooter>
//           </Card>
//         </TabsContent>
//       </Tabs>
//     </div>
//   )
// }

"use client"

import { useState } from "react"
import { Bell, AlertTriangle, FileText, ExternalLink, Radio, Play } from "lucide-react"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { toast } from "@/components/ui/use-toast"

export default function NetguardDashboard() {
  const [grafanaUrl, setGrafanaUrl] = useState("http://x.x.x.x:3001/d/app/netprobe")
  const [isSniffing, setIsSniffing] = useState(false)
  const [isDetecting, setIsDetecting] = useState(false)
  const [anomalyResults, setAnomalyResults] = useState(null)

  const startPacketSniffing = async () => {
    setIsSniffing(true)
    try {
      const response = await fetch("/api/start-sniffing", { method: "POST" })
      const data = await response.json()
      if (data.success) {
        toast({
          title: "Packet Sniffing Started",
          description: "Raw packet data is being captured and saved as CSV.",
        })
      } else {
        throw new Error(data.error)
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to start packet sniffing: " + error.message,
        variant: "destructive",
      })
    } finally {
      setIsSniffing(false)
    }
  }

  const detectAnomalies = async () => {
    setIsDetecting(true)
    try {
      const response = await fetch("/api/detect-anomalies", { method: "POST" })
      const data = await response.json()
      if (data.success) {
        setAnomalyResults(data.results)
        toast({
          title: "Anomaly Detection Complete",
          description: "Results have been updated.",
        })
      } else {
        throw new Error(data.error)
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to detect anomalies: " + error.message,
        variant: "destructive",
      })
    } finally {
      setIsDetecting(false)
    }
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-6">Netguard Dashboard</h1>

      <Tabs defaultValue="grafana" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="grafana">Grafana Dashboard</TabsTrigger>
          <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="packet-analysis">Packet Analysis</TabsTrigger>
        </TabsList>

        {/* ... (previous tab contents remain the same) ... */}

        <TabsContent value="packet-analysis" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Packet Analysis</CardTitle>
              <CardDescription>Capture packets and detect anomalies</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Button onClick={startPacketSniffing} disabled={isSniffing}>
                  {isSniffing ? (
                    <>
                      <Radio className="mr-2 h-4 w-4 animate-spin" />
                      Sniffing...
                    </>
                  ) : (
                    <>
                      <Play className="mr-2 h-4 w-4" />
                      Start Packet Sniffing
                    </>
                  )}
                </Button>
                <Button onClick={detectAnomalies} disabled={isDetecting}>
                  {isDetecting ? (
                    <>
                      <Radio className="mr-2 h-4 w-4 animate-spin" />
                      Detecting...
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="mr-2 h-4 w-4" />
                      Detect Anomalies
                    </>
                  )}
                </Button>
                {anomalyResults && (
                  <div className="mt-4">
                    <h3 className="text-lg font-semibold mb-2">Anomaly Detection Results:</h3>
                    <pre className="bg-gray-100 p-4 rounded-md overflow-x-auto">
                      {JSON.stringify(anomalyResults, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

