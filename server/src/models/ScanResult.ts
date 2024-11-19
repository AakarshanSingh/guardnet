import mongoose from "mongoose";

const scanResultSchema = new mongoose.Schema({
  email: { type: String, required: true },
  url: { type: String, required: true },
  cookies: { type: String, required: true },
  output: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

export const ScanResult = mongoose.model("ScanResult", scanResultSchema);
