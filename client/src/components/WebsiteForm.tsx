import { useState, useContext, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { ScanContext } from '../context/ScanContext';
import { AuthContext } from '../context/AuthContext';

const WebsiteForm = () => {
  const [url, setUrl] = useState('');
  const [cookies, setCookies] = useState('');
  const [showCookieField, setShowCookieField] = useState(false);
  const [urlError, setUrlError] = useState('');
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);

  const { submitScan, loading } = useContext(ScanContext);
  const { isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    const handler = () => {
      // No-op, just to avoid errors if event is not handled
    };
    window.addEventListener('open:login', handler);
    window.addEventListener('open:register', handler);
    return () => {
      window.removeEventListener('open:login', handler);
      window.removeEventListener('open:register', handler);
    };
  }, []);

  const validateUrl = (input: string) => {
    try {
      const newUrl = new URL(input);
      return newUrl.protocol === 'http:' || newUrl.protocol === 'https:';
    } catch (err) {
      return false;
    }
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUrl(e.target.value);
    if (urlError) setUrlError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateUrl(url)) {
      setUrlError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    if (!isAuthenticated) {
      window.dispatchEvent(new CustomEvent('open:login'));
      return;
    }

    const scanId = await submitScan(url, showCookieField ? cookies : undefined);

    if (scanId) {
      navigate(`/dashboard`);
    }
  };

  return (
    <div className='max-w-3xl mx-auto py-8'>
      <div className='text-center mb-12'>
        <h1 className='text-3xl font-bold text-indigo-900 mb-4'>
          Start Your Website Security Scan
        </h1>
        <p className='text-indigo-700 max-w-2xl mx-auto'>
          Enter your website URL below to begin analyzing for vulnerabilities,
          malware, and security issues.
        </p>
      </div>

      <div className='backdrop-blur-sm bg-white/80 rounded-xl border border-indigo-100 shadow-md p-6 md:p-8'>
        <form onSubmit={handleSubmit}>
          <div className='mb-6'>
            <label
              htmlFor='url'
              className='block text-sm font-medium text-indigo-700 mb-2'
            >
              Website URL
            </label>
            <div className='relative'>
              <div className='absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none'>
                <svg
                  xmlns='http://www.w3.org/2000/svg'
                  className='h-5 w-5 text-indigo-400'
                  fill='none'
                  viewBox='0 0 24 24'
                  stroke='currentColor'
                >
                  <path
                    strokeLinecap='round'
                    strokeLinejoin='round'
                    strokeWidth={2}
                    d='M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9'
                  />
                </svg>
              </div>
              <input
                type='text'
                id='url'
                name='url'
                value={url}
                onChange={handleUrlChange}
                placeholder='https://example.com'
                className={`w-full pl-10 pr-3 py-3 rounded-lg bg-indigo-50/60 border ${
                  urlError
                    ? 'border-red-300 focus:border-red-500'
                    : 'border-indigo-200 focus:border-indigo-500'
                } focus:ring-2 focus:ring-indigo-200 outline-none transition-colors`}
              />
            </div>
            {urlError && (
              <p className='mt-2 text-sm text-red-600'>{urlError}</p>
            )}
            <p className='mt-2 text-xs text-indigo-500'>
              Enter the complete URL including http:// or https://
            </p>
          </div>

          <div className='mb-6'>
            <button
              type='button'
              onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
              className='text-sm text-indigo-600 hover:text-indigo-800 font-medium flex items-center'
            >
              {showAdvancedOptions ? (
                <>
                  <svg
                    xmlns='http://www.w3.org/2000/svg'
                    className='h-4 w-4 mr-1'
                    fill='none'
                    viewBox='0 0 24 24'
                    stroke='currentColor'
                  >
                    <path
                      strokeLinecap='round'
                      strokeLinejoin='round'
                      strokeWidth={2}
                      d='M5 15l7-7 7 7'
                    />
                  </svg>
                  Hide Advanced Options
                </>
              ) : (
                <>
                  <svg
                    xmlns='http://www.w3.org/2000/svg'
                    className='h-4 w-4 mr-1'
                    fill='none'
                    viewBox='0 0 24 24'
                    stroke='currentColor'
                  >
                    <path
                      strokeLinecap='round'
                      strokeLinejoin='round'
                      strokeWidth={2}
                      d='M19 9l-7 7-7-7'
                    />
                  </svg>
                  Show Advanced Options
                </>
              )}
            </button>
          </div>

          {showAdvancedOptions && (
            <div className='mb-6 bg-indigo-50/60 rounded-lg p-4 border border-indigo-100'>
              <div className='mb-4'>
                <label className='flex items-center'>
                  <input
                    type='checkbox'
                    checked={showCookieField}
                    onChange={() => setShowCookieField(!showCookieField)}
                    className='rounded text-indigo-600 focus:ring-indigo-500 h-4 w-4'
                  />
                  <span className='ml-2 text-sm text-indigo-700'>
                    Include cookies for authenticated scanning
                  </span>
                </label>
                <p className='mt-1 text-xs text-indigo-500 ml-6'>
                  Required for scanning content behind login pages
                </p>
              </div>

              {showCookieField && (
                <div>
                  <label
                    htmlFor='cookies'
                    className='block text-sm font-medium text-indigo-700 mb-2'
                  >
                    Cookies
                  </label>
                  <textarea
                    id='cookies'
                    name='cookies'
                    value={cookies}
                    onChange={(e) => setCookies(e.target.value)}
                    placeholder='name=value; name2=value2'
                    rows={3}
                    className='w-full px-3 py-2 rounded-lg bg-white border border-indigo-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 outline-none transition-colors'
                  ></textarea>
                  <p className='mt-1 text-xs text-indigo-500'>
                    Enter cookies in standard format: name=value; name2=value2
                  </p>
                </div>
              )}
            </div>
          )}

          <div className='flex flex-col items-center gap-4'>
            <button
              type='submit'
              disabled={loading || !url}
              className={`w-full py-3 rounded-lg font-medium text-white ${
                loading || !url
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 shadow-md hover:shadow-lg transition-all duration-200  cursor-pointer'
              }`}
            >
              {loading ? (
                <div className='flex items-center justify-center'>
                  <svg
                    className='animate-spin h-5 w-5 mr-3 text-white'
                    xmlns='http://www.w3.org/2000/svg'
                    fill='none'
                    viewBox='0 0 24 24'
                  >
                    <circle
                      className='opacity-25'
                      cx='12'
                      cy='12'
                      r='10'
                      stroke='currentColor'
                      strokeWidth='4'
                    ></circle>
                    <path
                      className='opacity-75'
                      fill='currentColor'
                      d='M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z'
                    ></path>
                  </svg>
                  Processing...
                </div>
              ) : (
                <>Start Security Scan</>
              )}
            </button>
            <p className='text-sm text-center text-indigo-500'>
              By scanning, you agree to our{' '}
              <a href='#' className='text-indigo-600 hover:text-indigo-800'>
                Terms of Service
              </a>
            </p>
          </div>
        </form>
      </div>

      <div className='mt-8 bg-indigo-50/60 border border-indigo-100 rounded-lg p-4'>
        <h3 className='text-sm font-medium text-indigo-800 mb-2'>
          What happens during a scan?
        </h3>
        <p className='text-sm text-indigo-600'>
          Our scanner will analyze your website for common vulnerabilities
          including cross-site scripting (XSS), SQL injection, insecure
          configurations, outdated software, and more. The process is
          non-invasive and typically takes 2-5 minutes to complete.
        </p>
      </div>
    </div>
  );
};

export default WebsiteForm;
