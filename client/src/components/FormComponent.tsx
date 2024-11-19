import React, { useState } from "react";
import { toast } from "react-hot-toast"; // Import the toast function
import "./FormComponent.css";

interface FormData {
  websiteUrl: string;
  email: string;
  cookies: string;
  acceptTerms: boolean;
}

const FormComponent = () => {
  const [formData, setFormData] = useState<FormData>({
    websiteUrl: "",
    email: "",
    cookies: "",
    acceptTerms: false,
  });

  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.acceptTerms) {
      toast.error("You must accept the terms and conditions.");
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      console.log("Form submitted", formData);

      // Simulate successful form submission
      setFormData({
        websiteUrl: "",
        email: "",
        cookies: "",
        acceptTerms: false,
      });
      toast.success("Form submitted successfully!");
    } catch (error) {
      setSubmitError("There was an error submitting the form.");
      toast.error("Error submitting the form.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="form-container">
      <div className="form-wrapper">
        <h2>GuardNet - Vulnerability Testing</h2>
        <p className="form-description">
          Please enter your website's information, and we'll run a full security
          scan for vulnerabilities.
        </p>

        <form onSubmit={handleSubmit}>
          <div className="form-field">
            <label htmlFor="websiteUrl">Website URL</label>
            <input
              type="url"
              id="websiteUrl"
              name="websiteUrl"
              value={formData.websiteUrl}
              onChange={handleChange}
              placeholder="https://example.com"
              required
            />
            <div className="placeholder">Enter website URL</div>
          </div>

          <div className="form-field">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="youremail@example.com"
              required
            />
            <div className="placeholder">Enter your email (for report sending)</div>
          </div>

          <div className="form-field">
            <label htmlFor="cookies">Cookies</label>
            <input
              type="text"
              id="cookies"
              name="cookies"
              value={formData.cookies}
              onChange={handleChange}
              placeholder="cookie_data_here"
              required
            />
            <div className="placeholder">Enter cookies data</div>
          </div>

          <div className="checkbox-container">
            <input
              type="checkbox"
              name="acceptTerms"
              checked={formData.acceptTerms}
              onChange={handleChange}
            />
            <label>I accept the terms and conditions</label>
          </div>

          {submitError && <p className="error-message">{submitError}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className="submit-button"
          >
            {isSubmitting ? "Submitting..." : "Submit"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default FormComponent;
