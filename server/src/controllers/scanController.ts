import { Request, Response } from 'express';
import { exec } from 'child_process';
import path from 'path';
import { saveScanResultToDB } from '../db/scanResultService';
import { sendEmail } from './emailController';

export const scanWebsite = async (
  req: Request,
  res: Response
): Promise<void> => {
  const { email, cookies, url } = req.body;

  if (!email || !cookies || !url) {
    res.status(400).json({ error: 'Email, cookies, and URL are required.' });
    return;
  }

  try {
    const runPyPath = path.join(__dirname, '../../tools/run.py');
    const outputPath = path.join(__dirname, '../../tools/output/');

    const command = `python3 ${runPyPath} "${url}" '${JSON.stringify(
      cookies
    )}' "${outputPath}"`;
    console.log(`Executing command: ${command}`);

    exec(command, async (error, stdout, stderr) => {
      if (error) {
        console.error(`Error executing script: ${stderr}`);
        res.status(500).json({ error: 'Failed to run the scanner script.' });
        return;
      }

      const results = {
        email,
        url,
        cookies,
        output: stdout,
        timestamp: new Date(),
      };

      await saveScanResultToDB(results);
      await sendEmail(email, url, stdout);

      res
        .status(200)
        .json({ message: 'Scan completed and email sent!', results });
    });
  } catch (err) {
    // Narrow or cast the type of 'err' to 'Error'
    if (err instanceof Error) {
      console.error(`Error: ${err.message}`);
      res.status(500).json({ error: err.message });
    } else {
      // Handle unexpected error types
      console.error('Unknown error occurred:', err);
      res.status(500).json({ error: 'An unknown error occurred.' });
    }
  }
};
