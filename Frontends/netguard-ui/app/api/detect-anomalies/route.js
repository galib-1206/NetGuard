import { NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

export async function POST() {
  try {
    // Replace 'python3' with 'python' if you're on Windows
    const { stdout } = await execAsync("python3 /path/to/your/anomaly_detection_model.py")
    return NextResponse.json({ anomalies: stdout }, { status: 200 });
  } catch (error) {
    console.error("Error during anomaly detection:", error)
    return NextResponse.json({ error: "Failed to detect anomalies" }, { status: 500 });
  }
}

