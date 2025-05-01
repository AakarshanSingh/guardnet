import { useState, useContext } from 'react';
import { AuthContext } from '../../context/AuthContext';
import { toast } from 'react-hot-toast';

interface PasswordChangeModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const PasswordChangeModal: React.FC<PasswordChangeModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const { changePassword } = useContext(AuthContext);

  const resetForm = () => {
    setCurrentPassword('');
    setNewPassword('');
    setConfirmNewPassword('');
    setLoading(false);
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate form
    if (!currentPassword || !newPassword || !confirmNewPassword) {
      toast.error('All fields are required');
      return;
    }

    if (newPassword !== confirmNewPassword) {
      toast.error('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      toast.error('Password must be at least 8 characters long');
      return;
    }

    setLoading(true);

    try {
      const success = await changePassword(currentPassword, newPassword);

      if (success) {
        handleClose();
      }
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Modal Overlay - positioned fixed to the viewport */}
      <div
        className='fixed w-screen h-screen inset-0 bg-indigo-900/20 backdrop-blur-sm z-40'
        onClick={handleClose}
      ></div>
      <div className='fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4'>
        <div className='bg-gradient-to-br from-white/95 to-blue-50/95 backdrop-blur-sm rounded-2xl border border-blue-200/50 shadow-xl overflow-hidden m-2 sm:m-4 w-full max-w-md'>
          <div className='p-6 max-h-[90vh] overflow-y-auto'>
            {/* Header */}
            <div className='flex justify-between items-center mb-6'>
              <h2 className='text-2xl font-bold text-indigo-800'>
                Change Password
              </h2>
              <button
                onClick={handleClose}
                className='p-1 rounded-full hover:bg-indigo-100 transition-colors text-indigo-600'
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

            <form onSubmit={handleSubmit} className='space-y-4'>
              <div>
                <label
                  htmlFor='currentPassword'
                  className='block text-sm font-medium text-indigo-700 mb-1'
                >
                  Current Password
                </label>
                <input
                  type='password'
                  id='currentPassword'
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500'
                  placeholder='••••••••••'
                  disabled={loading}
                />
              </div>

              {/* New Password */}
              <div>
                <label
                  htmlFor='newPassword'
                  className='block text-sm font-medium text-indigo-700 mb-1'
                >
                  New Password
                </label>
                <input
                  type='password'
                  id='newPassword'
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500'
                  placeholder='••••••••••'
                  disabled={loading}
                />
              </div>

              {/* Confirm New Password */}
              <div>
                <label
                  htmlFor='confirmNewPassword'
                  className='block text-sm font-medium text-indigo-700 mb-1'
                >
                  Confirm New Password
                </label>
                <input
                  type='password'
                  id='confirmNewPassword'
                  value={confirmNewPassword}
                  onChange={(e) => setConfirmNewPassword(e.target.value)}
                  className='w-full px-4 py-2 bg-white/80 border border-blue-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500'
                  placeholder='••••••••••'
                  disabled={loading}
                />
              </div>

              {/* Submit Button */}
              <button
                type='submit'
                disabled={loading}
                className={`w-full py-3 px-4 rounded-lg text-white font-medium transition-all duration-300 shadow-md ${
                  loading
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 hover:shadow-lg'
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
                    <span>Updating Password...</span>
                  </div>
                ) : (
                  <span>Update Password</span>
                )}
              </button>
            </form>
          </div>
        </div>
      </div>
    </>
  );
};

export default PasswordChangeModal;
