import { ScanResult } from '../models/ScanResult';

export const saveScanResultToDB = async (result: any) => {
  try {
    const scanResult = new ScanResult(result);
    await scanResult.save();
    console.log('Scan result saved to database');
  } catch (error) {
    console.error(`Error saving to database: ${error}`);
    throw error;
  }
};
