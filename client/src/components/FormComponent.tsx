import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import axios from 'axios';

interface Cookie {
  name: string;
  value: string;
}

interface FormData {
  website_url: string;
  email: string;
  cookies: Cookie[];
  acceptTerms: boolean;
}

const FormComponent = () => {
  const [formData, setFormData] = useState<FormData>({
    website_url: '',
    email: '',
    cookies: [],
    acceptTerms: false,
  });

  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleCookieChange = (
    e: React.ChangeEvent<HTMLInputElement>,
    index: number
  ) => {
    const { name, value } = e.target;
    const newCookies = [...formData.cookies];
    newCookies[index] = { ...newCookies[index], [name]: value };
    setFormData({ ...formData, cookies: newCookies });
  };

  const addCookie = () => {
    setFormData({
      ...formData,
      cookies: [...formData.cookies, { name: '', value: '' }],
    });
  };

  const removeCookie = (index: number) => {
    const newCookies = formData.cookies.filter((_, i) => i !== index);
    setFormData({ ...formData, cookies: newCookies });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.acceptTerms) {
      toast.error('You must accept the terms and conditions.');
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const websiteUrl = formData.website_url.endsWith('/')
        ? formData.website_url
        : formData.website_url + '/';

      const data = {
        website_url: websiteUrl,
        email: formData.email,
        cookies: formData.cookies,
      };

      const response = await axios.post(
        'http://localhost:8000/api/scan',
        data,
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (response.status === 200) {
        toast.success('Scanning started');
      } else {
        throw new Error('Failed to submit the form.');
      }
    } catch (error) {
      setSubmitError('There was an error submitting the form.');
      toast.error('Error submitting the form.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex justify-center items-center">
      <div className="w-full max-w-3xl bg-gray-800 rounded-lg shadow-lg p-8">
        <h2 className="text-2xl font-bold mb-4 text-center">GuardNet - Vulnerability Testing</h2>
        <p className="text-gray-400 text-sm mb-6 text-center">
          Please enter your website's information, and we'll run a full security scan for vulnerabilities.
        </p>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="website_url" className="block text-sm font-medium mb-2">
              Website URL
            </label>
            <input
              type="url"
              id="website_url"
              name="website_url"
              value={formData.website_url}
              onChange={handleChange}
              className="w-full px-4 py-2 bg-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
              placeholder="https://example.com"
              required
            />
          </div>

          <div>
            <label htmlFor="email" className="block text-sm font-medium mb-2">
              Email
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              className="w-full px-4 py-2 bg-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
              placeholder="youremail@example.com"
              required
            />
          </div>

          <div>
            <h3 className="text-sm font-medium mb-2">Cookies</h3>
            {formData.cookies.map((cookie, index) => (
              <div key={index} className="flex space-x-4 items-center mb-2">
                <input
                  type="text"
                  name="name"
                  value={cookie.name}
                  onChange={(e) => handleCookieChange(e, index)}
                  className="flex-1 px-4 py-2 bg-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
                  placeholder="Cookie Name"
                  required
                />
                <input
                  type="text"
                  name="value"
                  value={cookie.value}
                  onChange={(e) => handleCookieChange(e, index)}
                  className="flex-1 px-4 py-2 bg-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
                  placeholder="Cookie Value"
                  required
                />
                <button
                  type="button"
                  onClick={() => removeCookie(index)}
                  className="text-red-500 hover:text-red-700 transition-colors"
                >
                  &times;
                </button>
              </div>
            ))}
            <button
              type="button"
              onClick={addCookie}
              className="px-4 py-2 bg-indigo-600 rounded-lg text-sm hover:bg-indigo-500 transition"
            >
              + Add Cookie
            </button>
          </div>

          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              name="acceptTerms"
              checked={formData.acceptTerms}
              onChange={handleChange}
              className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
            />
            <label className="text-sm">
              I accept the terms and conditions
            </label>
          </div>

          {submitError && <p className="text-red-500 text-sm">{submitError}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className={`w-full py-2 rounded-lg text-sm font-medium ${
              isSubmitting
                ? 'bg-gray-600 cursor-not-allowed'
                : 'bg-indigo-600 hover:bg-indigo-500 transition'
            }`}
          >
            {isSubmitting ? 'Submitting...' : 'Submit'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default FormComponent;
