import { useNavigate } from 'react-router-dom';

const LandingPage = () => {
  const navigate = useNavigate();

  const redirectToForm = () => {
    navigate('/check'); // Redirect to /check form page
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center px-6">
      <div className="text-center max-w-3xl">
        <h1 className="text-4xl font-bold mb-4">Welcome to GuardNet</h1>
        <p className="text-lg text-gray-300 mb-6">
          Test your website for vulnerabilities with ease. Perform detailed security scans and get actionable insights to strengthen your site's defenses.
        </p>

        <p className="text-sm text-gray-400 mb-8">
          Submit your website URL, email, and necessary cookie data to start scanning now.
        </p>

        <button
          onClick={redirectToForm}
          className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-6 py-3 rounded-lg shadow-md transition duration-300"
        >
          Start Scanning Now
        </button>
      </div>
    </div>
  );
};

export default LandingPage;
