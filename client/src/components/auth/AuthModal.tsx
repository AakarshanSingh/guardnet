import { useState, useContext } from 'react';
import { useNavigate } from 'react-router';
import { AuthContext } from '../../context/AuthContext';
import { toast } from 'react-hot-toast';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: 'login' | 'register';
}

const AuthModal: React.FC<AuthModalProps> = (props) => {
  const { isOpen, onClose, initialMode = 'login' } = props;
  const [mode, setMode] = useState<'login' | 'register'>(initialMode);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const { login, register } = useContext(AuthContext);
  const navigate = useNavigate();

  const resetForm = () => {
    setName('');
    setEmail('');
    setPassword('');
    setConfirmPassword('');
    setLoading(false);
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const validateForm = (): boolean => {
    if (mode === 'register') {
      if (!name.trim()) {
        toast.error('Name is required');
        return false;
      }
      if (password !== confirmPassword) {
        toast.error('Passwords do not match');
        return false;
      }
    }

    if (!email.trim()) {
      toast.error('Email is required');
      return false;
    }

    if (!password) {
      toast.error('Password is required');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) return;

    setLoading(true);

    try {
      if (mode === 'login') {
        const success = await login(email, password);
        if (success) {
          handleClose();
          navigate('/dashboard');
        }
      } else {
        const success = await register(name, email, password);
        if (success) {
          setMode('login');
          resetForm();
        }
      }
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className='fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4'>
      {/* Backdrop */}
      <div
        className='fixed inset-0 bg-indigo-900/20 backdrop-blur-sm transition-opacity duration-300 z-40'
        onClick={handleClose}
      ></div>

      {/* Modal */}
      <div className='relative w-full max-w-md sm:mx-auto transform transition-all duration-300 animate-fadeIn z-50'>
        <div className='bg-gradient-to-br from-white/95 to-blue-50/95 backdrop-blur-sm rounded-2xl border border-blue-200/50 shadow-xl overflow-hidden m-2 sm:m-4'>
          <div className='p-6 max-h-[90vh] overflow-y-auto'>
            {/* Header */}
            <div className='flex justify-between items-center mb-6'>
              <h2 className='text-2xl font-bold text-indigo-800'>
                {mode === 'login' ? 'Welcome Back' : 'Create Account'}
              </h2>
              <button
                onClick={handleClose}
                className='p-1 rounded-full hover:bg-indigo-100 transition-colors duration-200 text-indigo-600 cursor-pointer'
                aria-label='Close'
              >
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
                    d='M6 18L18 6M6 6l12 12'
                  />
                </svg>
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className='space-y-4'>
              {/* Name - only for register */}
              {mode === 'register' && (
                <div>
                  <label
                    htmlFor='name'
                    className='block text-sm font-medium text-indigo-700 mb-1'
                  >
                    Name
                  </label>
                  <input
                    type='text'
                    id='name'
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200'
                    placeholder='Enter your name'
                    disabled={loading}
                  />
                </div>
              )}

              {/* Email */}
              <div>
                <label
                  htmlFor='email'
                  className='block text-sm font-medium text-indigo-700 mb-1'
                >
                  Email
                </label>
                <input
                  type='email'
                  id='email'
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200'
                  placeholder='your.email@example.com'
                  disabled={loading}
                />
              </div>

              {/* Password */}
              <div>
                <label
                  htmlFor='password'
                  className='block text-sm font-medium text-indigo-700 mb-1'
                >
                  Password
                </label>
                <input
                  type='password'
                  id='password'
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200'
                  placeholder='••••••••••'
                  disabled={loading}
                />
              </div>

              {/* Confirm Password - only for register */}
              {mode === 'register' && (
                <div>
                  <label
                    htmlFor='confirmPassword'
                    className='block text-sm font-medium text-indigo-700 mb-1'
                  >
                    Confirm Password
                  </label>
                  <input
                    type='password'
                    id='confirmPassword'
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors duration-200'
                    placeholder='••••••••••'
                    disabled={loading}
                  />
                </div>
              )}

              {/* Submit Button */}
              <button
                type='submit'
                disabled={loading}
                className={`w-full py-3 px-4 rounded-lg text-white font-medium transition-all duration-300 shadow-md ${
                  loading
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 hover:shadow-lg cursor-pointer transform hover:translate-y-[-1px]'
                }`}
              >
                {loading ? (
                  <div className='flex items-center justify-center'>
                    <svg
                      className='animate-spin h-5 w-5 mr-2'
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
                    <span>
                      {mode === 'login'
                        ? 'Logging in...'
                        : 'Creating account...'}
                    </span>
                  </div>
                ) : (
                  <span>{mode === 'login' ? 'Sign In' : 'Create Account'}</span>
                )}
              </button>
            </form>

            {/* Toggle Mode */}
            <div className='mt-6 text-center text-sm'>
              {mode === 'login' ? (
                <p className='text-indigo-700'>
                  Don't have an account?{' '}
                  <button
                    onClick={() => setMode('register')}
                    className='text-indigo-500 hover:text-indigo-700 font-medium transition-colors duration-200 focus:outline-none cursor-pointer'
                    disabled={loading}
                  >
                    Sign up
                  </button>
                </p>
              ) : (
                <p className='text-indigo-700'>
                  Already have an account?{' '}
                  <button
                    onClick={() => setMode('login')}
                    className='text-indigo-500 hover:text-indigo-700 font-medium transition-colors duration-200 focus:outline-none cursor-pointer'
                    disabled={loading}
                  >
                    Sign in
                  </button>
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthModal;
