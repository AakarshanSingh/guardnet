import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

interface VulnerabilityCounts {
  SQLi: number;
  XSS: number;
  LFI: number;
  CMD: number;
  WordPress: number;
}

const ResultsPage = () => {
  const navigate = useNavigate();
  const [vulnerabilities, setVulnerabilities] = useState<string[]>([]);
  const [counts, setCounts] = useState<VulnerabilityCounts | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const response = await axios.get('http://localhost:8000/api/combined-report');
        if (response.status === 200) {
          const reportText = await response.data;

          const lines = reportText.split('\n');
          const countsIndex = lines.findIndex((line: string) =>
            line.startsWith('Total Vulnerabilities')
          );
          const detailsIndex = lines.findIndex((line: string) =>
            line.startsWith('Detailed Vulnerabilities')
          );

          if (countsIndex !== -1 && detailsIndex !== -1) {
            const countsText = lines.slice(countsIndex + 1, detailsIndex).join('\n');
            const countsData: VulnerabilityCounts = {
              SQLi: parseInt(countsText.match(/SQLi Vulnerabilities: (\d+)/)?.[1] || '0'),
              XSS: parseInt(countsText.match(/XSS Vulnerabilities: (\d+)/)?.[1] || '0'),
              LFI: parseInt(countsText.match(/LFI Vulnerabilities: (\d+)/)?.[1] || '0'),
              CMD: parseInt(countsText.match(/CMD Vulnerabilities: (\d+)/)?.[1] || '0'),
              WordPress: parseInt(countsText.match(/WordPress Vulnerabilities: (\d+)/)?.[1] || '0'),
            };

            const vulnerabilitiesData = lines.slice(detailsIndex + 1);

            setCounts(countsData);
            setVulnerabilities(vulnerabilitiesData);
          }
        }
      } catch (error) {
        console.error('Error fetching report:', error);
        navigate('/'); // Redirect to home on error
      } finally {
        setIsLoading(false);
      }
    };

    fetchReport();
  }, [navigate]);

  const handleDownloadReport = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/combined-report', {
        responseType: 'blob',
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'combined_report.txt';
      a.click();
    } catch (error) {
      console.error('Error downloading report:', error);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <p className="text-lg">Loading report...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white px-6 py-12">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">Vulnerability Scan Results</h1>

        {counts && (
          <div className="bg-gray-800 p-6 rounded-lg mb-8 shadow-lg">
            <h2 className="text-2xl font-semibold mb-4">Summary</h2>
            <p className="text-lg font-medium mb-4">
              Total Vulnerabilities:{' '}
              <span className="text-blue-400">
                {Object.values(counts).reduce((a, b) => a + b, 0)}
              </span>
            </p>
            <ul className="space-y-2 text-gray-300">
              <li>SQLi: {counts.SQLi}</li>
              <li>XSS: {counts.XSS}</li>
              <li>LFI: {counts.LFI}</li>
              <li>CMD: {counts.CMD}</li>
              <li>WordPress: {counts.WordPress}</li>
            </ul>
          </div>
        )}

        <h2 className="text-2xl font-semibold mb-4">Detailed Vulnerabilities</h2>
        <ul className="bg-gray-800 p-6 rounded-lg shadow-lg space-y-2">
          {vulnerabilities.map((vuln, idx) => (
            <li key={idx} className="text-gray-300">
              {vuln}
            </li>
          ))}
        </ul>

        <div className="mt-8">
          <button
            onClick={handleDownloadReport}
            className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-6 py-3 rounded-lg shadow-md transition duration-300"
          >
            Download Full Report
          </button>
        </div>
      </div>
    </div>
  );
};

export default ResultsPage;
