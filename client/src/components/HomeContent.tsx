import { useContext } from 'react';
import { useNavigate } from 'react-router';
import { AuthContext } from '../context/AuthContext';

const HomeContent = () => {
  const { isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleGetStarted = () => {
    if (isAuthenticated) {
      navigate('/scan');
    } else {
      window.dispatchEvent(new CustomEvent('open:register'));
    }
  };

  const handleStartDemo = () => {
    navigate('/scan');
  };

  return (
    <div className='min-h-screen'>
      {/* Hero Section with enhanced animation */}
      <div className='py-16 md:py-24 relative overflow-hidden'>
        {/* Background decoration elements */}
        <div className='absolute w-64 h-64 rounded-full bg-indigo-100/50 -top-20 -left-20 blur-3xl'></div>
        <div className='absolute w-96 h-96 rounded-full bg-blue-100/50 -bottom-40 -right-40 blur-3xl'></div>

        <div className='max-w-3xl mx-auto text-center relative'>
          <h1 className='text-4xl md:text-5xl font-bold text-indigo-900 mb-6 animate-slideInUp'>
            Scan your website for Potential Vulnerabilities
          </h1>
          <p
            className='text-xl text-indigo-700 mb-10 max-w-2xl mx-auto animate-fadeIn'
            style={{ animationDelay: '0.2s' }}
          >
            Identify vulnerabilities, detect threats, and secure your online
            presence with GuardNet's comprehensive security scanning platform.
          </p>
          <div
            className='flex flex-col sm:flex-row gap-4 justify-center animate-fadeIn'
            style={{ animationDelay: '0.4s' }}
          >
            <button
              onClick={handleGetStarted}
              className='py-3 px-8 bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 text-white rounded-lg shadow-md hover:shadow-lg transition-all duration-300 text-lg font-medium cursor-pointer hover:-translate-y-1'
            >
              Get Started
            </button>
            <button
              onClick={handleStartDemo}
              className='py-3 px-8 bg-indigo-100 text-indigo-700 rounded-lg hover:bg-indigo-200 text-lg font-medium transition-all duration-300 cursor-pointer hover:-translate-y-1'
            >
              Try Demo
            </button>
          </div>
        </div>
      </div>

      {/* Features Section with staggered animation */}
      <div className='py-16 bg-gradient-soft'>
        <div className='max-w-6xl mx-auto px-4 sm:px-6 lg:px-8'>
          <div className='text-center mb-12 animate-fadeIn'>
            <h2 className='text-3xl font-bold text-indigo-900 mb-4'>
              Comprehensive Website Security
            </h2>
            <p className='text-xl text-indigo-700 max-w-3xl mx-auto'>
              Our advanced scanning technology identifies vulnerabilities before
              attackers can exploit them.
            </p>
          </div>

          <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8'>
            {/* Feature 1 */}
            <div
              className='backdrop-blur-sm bg-white/80 rounded-xl border border-indigo-100 shadow-md p-6 hover:shadow-lg transition-all duration-300 hover:-translate-y-2 card-hover-effect animate-fadeIn'
              style={{ animationDelay: '0.1s' }}
            >
              <div className='h-12 w-12 bg-indigo-100 rounded-lg text-indigo-600 flex items-center justify-center mb-4'>
                <svg
                  xmlns='http://www.w3.org/2000/svg'
                  className='h-6 w-6'
                  fill='none'
                  viewBox='0 0 24 24'
                  stroke='currentColor'
                >
                  <path
                    strokeLinecap='round'
                    strokeLinejoin='round'
                    strokeWidth={2}
                    d='M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01'
                  />
                </svg>
              </div>
              <h3 className='text-xl font-bold text-indigo-900 mb-2'>
                Vulnerability Assessment
              </h3>
              <p className='text-indigo-700'>
                Identify security weaknesses in your website code, server
                configuration, and third-party components.
              </p>
            </div>

            {/* Feature 2 */}
            <div
              className='backdrop-blur-sm bg-white/80 rounded-xl border border-indigo-100 shadow-md p-6 hover:shadow-lg transition-all duration-300 hover:-translate-y-2 card-hover-effect animate-fadeIn'
              style={{ animationDelay: '0.2s' }}
            >
              <div className='h-12 w-12 bg-indigo-100 rounded-lg text-indigo-600 flex items-center justify-center mb-4'>
                <svg
                  xmlns='http://www.w3.org/2000/svg'
                  className='h-6 w-6'
                  fill='none'
                  viewBox='0 0 24 24'
                  stroke='currentColor'
                >
                  <path
                    strokeLinecap='round'
                    strokeLinejoin='round'
                    strokeWidth={2}
                    d='M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z'
                  />
                </svg>
              </div>
              <h3 className='text-xl font-bold text-indigo-900 mb-2'>
                SSL/TLS Certificate Validation
              </h3>
              <p className='text-indigo-700'>
                Verify your encryption protocols, detect expired certificates, and ensure secure 
                connections between your website and visitors.
              </p>
            </div>

            {/* Feature 3 */}
            <div
              className='backdrop-blur-sm bg-white/80 rounded-xl border border-indigo-100 shadow-md p-6 hover:shadow-lg transition-all duration-300 hover:-translate-y-2 card-hover-effect animate-fadeIn'
              style={{ animationDelay: '0.3s' }}
            >
              <div className='h-12 w-12 bg-indigo-100 rounded-lg text-indigo-600 flex items-center justify-center mb-4'>
                <svg
                  xmlns='http://www.w3.org/2000/svg'
                  className='h-6 w-6'
                  fill='none'
                  viewBox='0 0 24 24'
                  stroke='currentColor'
                >
                  <path
                    strokeLinecap='round'
                    strokeLinejoin='round'
                    strokeWidth={2}
                    d='M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z'
                  />
                </svg>
              </div>
              <h3 className='text-xl font-bold text-indigo-900 mb-2'>
                Real-time Reporting
              </h3>
              <p className='text-indigo-700'>
                Get instant, detailed reports on potential threats with clear
                remediation steps to quickly address vulnerabilities.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Call to Action Section */}
      <div className='py-16 bg-white relative overflow-hidden'>
        {/* Decorative background element */}
        <div className='absolute inset-0 bg-gradient-to-br from-indigo-50/40 to-blue-50/40 transform -skew-y-6'></div>

        <div className='max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 relative'>
          <div className='text-center max-w-3xl mx-auto animate-fadeIn'>
            <h2 className='text-3xl font-bold text-indigo-900 mb-4'>
              Ready to Secure Your Website?
            </h2>
            <p className='text-xl text-indigo-700 mb-8'>
              Don't wait for a security breach. Proactively protect your website
              and user data now.
            </p>
            <button
              onClick={handleGetStarted}
              className='py-3 px-8 bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 text-white rounded-lg shadow-md hover:shadow-lg transition-all duration-300 text-lg font-medium cursor-pointer hover:-translate-y-1'
            >
              {isAuthenticated ? 'Start Scanning Now' : 'Create Free Account'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomeContent;
