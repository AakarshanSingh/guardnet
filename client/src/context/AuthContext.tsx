import { createContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

// Define User type
export interface User {
  id: number;
  name: string;
  email: string;
}

// Define context type
interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  register: (name: string, email: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  changePassword: (
    currentPassword: string,
    newPassword: string
  ) => Promise<boolean>;
}

// Create context with default values
export const AuthContext = createContext<AuthContextType>({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  login: async () => false,
  register: async () => false,
  logout: async () => {},
  changePassword: async () => false,
});

// Set up axios defaults
axios.defaults.baseURL = 'http://localhost:8000';
axios.defaults.withCredentials = true;
axios.defaults.headers.common['Access-Control-Allow-Origin'] = '*';
axios.defaults.headers.common['Content-Type'] = 'application/json';

// Add axios interceptor to include token in requests
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Add axios interceptor for response errors to handle 401 Unauthorized errors
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    // Don't automatically logout on 401 during token validation
    if (
      error.response?.status === 401 &&
      !error.config.url.includes('validate-token')
    ) {
      // Only clear auth state for non-validation API calls that return 401
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.dispatchEvent(new CustomEvent('auth:logout'));
    }
    return Promise.reject(error);
  }
);

interface AuthProviderProps {
  children: ReactNode;
}

const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Listen for logout events from the interceptor
  useEffect(() => {
    const handleLogout = () => {
      setUser(null);
      setIsAuthenticated(false);
    };
    
    window.addEventListener('auth:logout', handleLogout);
    return () => window.removeEventListener('auth:logout', handleLogout);
  }, []);

  // Check if user is authenticated on load
  useEffect(() => {
    const checkAuthentication = async () => {
      setIsLoading(true);
      try {
        // First check if we have a token in local storage
        const token = localStorage.getItem('token');
        const storedUser = localStorage.getItem('user');
        
        if (!token || !storedUser) {
          // No stored credentials, user is not logged in
          setIsAuthenticated(false);
          setUser(null);
          setIsLoading(false);
          return;
        }
        
        // If we have stored user data, set it immediately to prevent flashing unauthenticated UI
        try {
          const parsedUser = JSON.parse(storedUser);
          setUser(parsedUser);
          setIsAuthenticated(true);
        } catch (parseError) {
          console.error('Failed to parse stored user data:', parseError);
          localStorage.removeItem('user');
          setIsAuthenticated(false);
          setUser(null);
          setIsLoading(false);
          return;
        }
        
        // Then try to validate the token with the backend but with a timeout
        const validateTokenWithTimeout = async () => {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
          
          try {
            const response = await axios.post('/api/validate-token', {}, {
              signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            // Only update state if the token is explicitly invalid
            if (response.data && response.data.valid === false) {
              localStorage.removeItem('token');
              localStorage.removeItem('user');
              setIsAuthenticated(false);
              setUser(null);
            }
          } catch (error) {
            clearTimeout(timeoutId);
            
            // Type guard to ensure error is treated as an object with potential properties
            const apiError = error as { name?: string; response?: any };
            
            // If API call fails due to timeout or server issues, keep user logged in
            // This way they won't be logged out just because of API/connection issues
            if (apiError.name === 'AbortError' || !apiError.response) {
              console.warn('Token validation timed out or failed, keeping user logged in');
            } else if (apiError.response?.status === 401) {
              // If server explicitly says token is invalid, log out
              localStorage.removeItem('token');
              localStorage.removeItem('user');
              setIsAuthenticated(false);
              setUser(null);
            }
            // For any other error, keep the user logged in
          }
        };
        
        // Start validation but don't wait for it
        validateTokenWithTimeout();
      } catch (error) {
        console.error('Authentication initialization error:', error);
      } finally {
        setIsLoading(false);
      }
    };

    checkAuthentication();
  }, []);

  // Login function
  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await axios.post('/api/login', {
        email,
        password,
      });
      const data = response.data.data;

      if (data.access_token) {
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setIsAuthenticated(true);
        setUser(data.user);
        toast.success('Logged in successfully');
        return true;
      }

      toast.error(response.data.message || 'Login failed');
      return false;
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 'Login failed';
      toast.error(errorMessage);
      console.error('Login error:', error);
      return false;
    }
  };

  // Register function
  const register = async (
    name: string,
    email: string,
    password: string
  ): Promise<boolean> => {
    try {
      const response = await axios.post('/api/signup', {
        name,
        email,
        password,
      });

      if (response.status === 201) {
        toast.success('Registration successful!');
        return true;
      }

      toast.error(response.data.message || 'Registration failed');
      return false;
    } catch (error: any) {
      const errorMessage =
        error.response?.data?.message || 'Registration failed';
      toast.error(errorMessage);
      console.error('Registration error:', error);
      return false;
    }
  };

  // Logout function
  const logout = async (): Promise<void> => {
    try {
      await axios.post('/api/logout');
    } catch (error) {
      console.error('Logout API error:', error);
    } finally {
      // Always clear local storage and state regardless of API response
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setIsAuthenticated(false);
      setUser(null);
      toast.success('Logged out successfully');
    }
  };

  // Change password function
  const changePassword = async (
    currentPassword: string,
    newPassword: string
  ): Promise<boolean> => {
    try {
      const response = await axios.post('/api/change-password', {
        current_password: currentPassword,
        new_password: newPassword,
      });

      if (response.statusText === 'OK') {
        toast.success('Password changed successfully');
        return true;
      }

      toast.error(response.data.message || 'Failed to change password');
      return false;
    } catch (error: any) {
      const errorMessage =
        error.response?.data?.message || 'Failed to change password';
      toast.error(errorMessage);
      console.error('Password change error:', error);
      return false;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        login,
        register,
        logout,
        changePassword,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export default AuthProvider;
