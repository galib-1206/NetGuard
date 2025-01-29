import { NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

export async function POST() {
  try {
    // Replace 'python3' with 'python' if you're on Windows
    await execAsync("python3 /path/to/your/packet_sniffer.py")
    return NextResponse.json({ message: "Packet sniffing completed" }, { status: 200 });
  } catch (error) {
    console.error("Error during packet sniffing:", error)
    return NextResponse.json({ error: "Failed to start packet sniffing" }, { status: 500 });
  }
}

