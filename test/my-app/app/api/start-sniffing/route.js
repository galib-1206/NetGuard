import { NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

export async function POST() {
  try {
    // Execute the Python script for packet sniffing
    await execAsync("python path/to/your/packet_sniffer.py")
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Error starting packet sniffing:", error)
    return NextResponse.json({ success: false, error: error.message }, { status: 500 })
  }
}

