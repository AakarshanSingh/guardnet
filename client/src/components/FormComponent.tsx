import React, { useState } from 'react';
import { toast } from 'react-hot-toast'; // Import the toast function
import axios from 'axios'; // Import axios
import './FormComponent.css';

interface Cookie {
  name: string;
  value: string;
}

interface FormData {
  website_url: string;
  email: string;
  cookies: Cookie[]; // Change cookies to an array of objects
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

    // Check if terms are accepted
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

      // Send data to the backend API using axios
      const response = await axios.post(
        'http://localhost:8000/api/scan',
        data,
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      // Check if the response is successful
      if (response.status === 200) {
        // setFormData({
        //   website_url: '',
        //   email: '',
        //   cookies: [],
        //   acceptTerms: false,
        // });
        toast.success('Scanning started');

      } else {
        throw new Error('Failed to submit the form.');
      }

      console.log(response)
    } catch (error) {
      setSubmitError('There was an error submitting the form.');
      toast.error('Error submitting the form.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className='form-container'>
      <div className='form-wrapper'>
        <h2>GuardNet - Vulnerability Testing</h2>
        <p className='form-description'>
          Please enter your website's information, and we'll run a full security
          scan for vulnerabilities.
        </p>

        <form onSubmit={handleSubmit}>
          <div className='form-field'>
            <label htmlFor='website_url'>Website URL</label>
            <input
              type='url'
              id='website_url'
              name='website_url'
              value={formData.website_url}
              onChange={handleChange}
              placeholder='https://example.com'
              required
            />
            <div className='placeholder'>Enter website URL</div>
          </div>

          <div className='form-field'>
            <label htmlFor='email'>Email</label>
            <input
              type='email'
              id='email'
              name='email'
              value={formData.email}
              onChange={handleChange}
              placeholder='youremail@example.com'
              required
            />
            <div className='placeholder'>
              Enter your email (for report sending)
            </div>
          </div>

          {/* Cookie Fields */}
          <div className='cookies-container'>
            <h3>Cookies</h3>
            {formData.cookies.map((cookie, index) => (
              <div key={index} className='cookie-field'>
                <input
                  type='text'
                  name='name'
                  value={cookie.name}
                  onChange={(e) => handleCookieChange(e, index)}
                  placeholder='Cookie Name'
                  required
                />
                <input
                  type='text'
                  name='value'
                  value={cookie.value}
                  onChange={(e) => handleCookieChange(e, index)}
                  placeholder='Cookie Value'
                  required
                />
                <button
                  type='button'
                  onClick={() => removeCookie(index)}
                  className='remove-cookie-button'
                >
                  &ndash;
                </button>
              </div>
            ))}
            <button
              type='button'
              onClick={addCookie}
              className='add-cookie-button'
            >
              + Add Cookie
            </button>
          </div>

          <div className='checkbox-container'>
            <input
              type='checkbox'
              name='acceptTerms'
              checked={formData.acceptTerms}
              onChange={handleChange}
            />
            <label>I accept the terms and conditions</label>
          </div>

          {submitError && <p className='error-message'>{submitError}</p>}

          <button
            type='submit'
            disabled={isSubmitting}
            className='submit-button'
          >
            {isSubmitting ? 'Submitting...' : 'Submit'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default FormComponent;
