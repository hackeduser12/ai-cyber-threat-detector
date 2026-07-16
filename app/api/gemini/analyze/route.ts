import { GoogleGenAI, Type } from "@google/genai";
import { NextRequest, NextResponse } from "next/server";

// Initialize Gemini SDK with telemetry header as required by the guidelines
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { duration, packetCount, bytesTransferred, failedLogins, label, confidence } = body;

    const trafficDesc = `
      Connection Duration: ${duration} seconds
      Packet Count: ${packetCount}
      Bytes Transferred: ${bytesTransferred} bytes
      Failed Login Attempts: ${failedLogins}
      Classifier Result: ${label === 1 ? '🚨 Threat Detected' : '✅ Benign'}
      Classifier Confidence: ${(confidence * 100).toFixed(1)}%
    `;

    const systemInstruction = `
      You are an expert senior Tier-3 Security Operations Center (SOC) Analyst and Threat Intelligence Officer.
      Your task is to analyze network traffic metrics flagged by a machine learning model, classify the attack vector, explain the indicators of compromise, assign a risk level (Low, Medium, High, Critical), and provide actionable, specific mitigation/remediation instructions.
      Keep your analysis precise, professional, technical but accessible, and highly practical. Avoid generic platitudes.
    `;

    const prompt = `
      Analyze the following network flow metrics and provide a structured security diagnostic report in JSON format:
      ${trafficDesc}
    `;

    // Request structured JSON response
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          required: ["classification", "riskLevel", "summary", "technicalDetails", "mitigationSteps"],
          properties: {
            classification: {
              type: Type.STRING,
              description: "Attack vector name (e.g., Credential Brute-Force, Distributed Denial of Service (DDoS), Data Exfiltration, or Baseline Normal Traffic)",
            },
            riskLevel: {
              type: Type.STRING,
              description: "One of: Low, Medium, High, Critical",
            },
            summary: {
              type: Type.STRING,
              description: "High-level summary of the analysis",
            },
            technicalDetails: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "List of technical reasoning points explaining why this behavior is benign or anomalous",
            },
            mitigationSteps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Step-by-step actionable remediation steps to block or mitigate this specific threat",
            },
          },
        },
      },
    });

    const text = response.text;
    if (!text) {
      throw new Error("No response received from the Gemini model");
    }

    const report = JSON.parse(text);
    return NextResponse.json(report);
  } catch (error: any) {
    console.error("Gemini threat analysis failed:", error);
    return NextResponse.json(
      { error: error.message || "Failed to analyze cyber threat metrics via Gemini" },
      { status: 500 }
    );
  }
}
