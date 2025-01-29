"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertCircle, CheckCircle2 } from "lucide-react"

export default function PacketAnalyzer() {
  const [isSniffing, setIsSniffing] = useState(false)
  const [sniffingComplete, setSniffingComplete] = useState(false)
  const [anomalyResults, setAnomalyResults] = useState(null)
  const [isLoading, setIsLoading] = useState(false)

  const startSniffing = async () => {
    setIsSniffing(true)
    setIsLoading(true)
    try {
      const response = await fetch("/api/start-sniffing", { method: "POST" })
      if (response.ok) {
        setSniffingComplete(true)
      } else {
        throw new Error("Failed to start sniffing")
      }
    } catch (error) {
      console.error("Error starting packet sniffing:", error)
      alert("Failed to start packet sniffing. Please try again.")
    } finally {
      setIsSniffing(false)
      setIsLoading(false)
    }
  }

  const detectAnomalies = async () => {
    setIsLoading(true)
    try {
      const response = await fetch("/api/detect-anomalies", { method: "POST" })
      if (response.ok) {
        const results = await response.json()
        setAnomalyResults(results.anomalies)
      } else {
        throw new Error("Failed to detect anomalies")
      }
    } catch (error) {
      console.error("Error detecting anomalies:", error)
      alert("Failed to detect anomalies. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    (<Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>Packet Analyzer</CardTitle>
        <CardDescription>Capture packets and detect anomalies</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button
          onClick={startSniffing}
          disabled={isSniffing || isLoading}
          className="w-full">
          {isSniffing ? "Sniffing..." : "Start Packet Sniffing"}
        </Button>
        {sniffingComplete && (
          <div className="flex items-center text-green-600">
            <CheckCircle2 className="mr-2" />
            Packet sniffing complete
          </div>
        )}
        <Button
          onClick={detectAnomalies}
          disabled={!sniffingComplete || isLoading}
          className="w-full">
          Detect Anomalies
        </Button>
        {anomalyResults && (
          <div className="mt-4 p-4 bg-yellow-100 rounded-md">
            <h3 className="font-semibold flex items-center">
              <AlertCircle className="mr-2 text-yellow-600" />
              Anomaly Detection Results
            </h3>
            <pre className="mt-2 whitespace-pre-wrap">{anomalyResults}</pre>
          </div>
        )}
      </CardContent>
      <CardFooter>
        <p className="text-sm text-gray-500">
          Click "Start Packet Sniffing" to begin capturing packets, then "Detect Anomalies" to analyze the captured
          data.
        </p>
      </CardFooter>
    </Card>)
  );
}

