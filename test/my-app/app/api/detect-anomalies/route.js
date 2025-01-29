import { NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

export async function POST() {
  try {
    // Execute the Python script for anomaly detection
    const { stdout } = await execAsync("python path/to/your/anomaly_detection.py")
    const results = JSON.parse(stdout)
    return NextResponse.json({ success: true, results })
  } catch (error) {
    console.error("Error detecting anomalies:", error)
    return NextResponse.json({ success: false, error: error.message }, { status: 500 })
  }
}

