import { useState } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

interface VulnerabilityCounts {
  [key: string]: number;
}

const ResultsPage = () => {
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState<string[]>([]);
  const [counts, setCounts] = useState<VulnerabilityCounts | null>(null);
  const [downloadLink, setDownloadLink] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCounts(null);
    setVulnerabilities([]);
    setDownloadLink(null);

    await toast.promise(
      axios
        .post('http://localhost:8000/api/combined-report', {
          website_url: websiteUrl,
        })
        .then((response) => {
          if (response.status === 200 && response.data) {
            const { summary, details, website_url } = response.data;

            setCounts(summary);
            setVulnerabilities(
              details.map((item: any) => `${item.type}: ${item.detail}`)
            );
            setDownloadLink(website_url);
          } else {
            throw new Error('Unexpected response from the server.');
          }
        })
        .catch((error) => {
          console.error('Error fetching the report:', error);
          throw new Error(
            error.response?.data?.message || 'Failed to fetch the report.'
          );
        }),
      {
        loading: 'Fetching the report...',
        success: 'Report fetched successfully!',
        error: 'Failed to fetch the report. Please try again.',
      }
    );
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white px-6 py-12">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">Vulnerability Scan Tool</h1>
        <form
          onSubmit={handleSubmit}
          className="bg-gray-800 p-6 rounded-lg shadow-lg mb-8"
        >
          <label
            htmlFor="websiteUrl"
            className="block text-sm font-medium mb-2"
          >
            Enter Website URL
          </label>
          <input
            type="text"
            id="websiteUrl"
            value={websiteUrl}
            onChange={(e) => setWebsiteUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-3 py-2 rounded-md bg-gray-700 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 mb-4 text-sm"
            required
          />
          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium px-3 py-2 rounded-md shadow-md transition text-sm"
          >
            Generate Report
          </button>
        </form>

        {downloadLink && (
          <div className="mt-6">
            <a
              href={`http://localhost:8000${downloadLink}`}
              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md shadow-md transition text-sm"
              download
            >
              Download Report
            </a>
          </div>
        )}

        {counts && (
          <div className="bg-gray-800 p-6 rounded-lg mb-8 shadow-lg mt-6">
            <h2 className="text-2xl font-semibold mb-4">Summary</h2>
            <p className="text-lg font-medium mb-4">
              Total Vulnerabilities:{' '}
              <span className="text-blue-400">
                {Object.values(counts).reduce((a, b) => a + b, 0)}
              </span>
            </p>
            <ul className="space-y-2 text-gray-300">
              {Object.entries(counts).map(([type, count]) => (
                <li key={type}>
                  {type} Vulnerabilities: {count}
                </li>
              ))}
            </ul>
          </div>
        )}

        {vulnerabilities.length > 0 && (
          <div className="mt-6">
            <h2 className="text-2xl font-semibold mb-4">
              Detailed Vulnerabilities
            </h2>
            <ul className="bg-gray-800 p-6 rounded-lg shadow-lg space-y-2">
              {vulnerabilities.map((vuln, idx) => (
                <li key={idx} className="text-gray-300">
                  {vuln}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
};

export default ResultsPage;
