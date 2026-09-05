import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import Logo from '../../components/ui/Logo';
import loginBg from '../../assets/login-bg.png';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useApp();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  
  // Validation States
  const [loading, setLoading] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(null);

  const validateEmail = (val: string) => {
    if (!val) {
      return 'Email address is required';
    }
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!regex.test(val)) {
      return 'Please enter a valid email address';
    }
    return null;
  };

  const validatePassword = (val: string) => {
    if (!val) {
      return 'Password is required';
    }
    if (val.length < 4) {
      return 'Password must be at least 4 characters';
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailError(null);
    setPasswordError(null);
    setGeneralError(null);

    const emailErr = validateEmail(email);
    const passErr = validatePassword(password);

    if (emailErr || passErr) {
      setEmailError(emailErr);
      setPasswordError(passErr);
      return;
    }

    setLoading(true);
    try {
      const success = await login(email);
      if (success) {
        navigate('/dashboard');
      } else {
        setGeneralError('Invalid credentials. Please try again.');
      }
    } catch (err) {
      setGeneralError('An unexpected error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-surface-container-lowest text-on-surface antialiased min-h-screen flex flex-col relative overflow-hidden font-body-md w-full">
      {/* Sophisticated Abstract Background */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        <div 
          className="absolute inset-0 bg-cover bg-center opacity-30 mix-blend-screen" 
          style={{ 
            backgroundImage: `url(${loginBg})` 
          }}
        ></div>
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-surface-container-lowest/80 to-surface-container-lowest"></div>
        <div className="absolute top-1/4 left-1/4 w-[800px] h-[800px] bg-primary/10 rounded-full blur-[120px] mix-blend-lighten transform -translate-x-1/2 -translate-y-1/2"></div>
      </div>

      {/* Main Content Canvas */}
      <main className="flex-grow flex items-center justify-center relative z-10 px-container-padding py-stack-lg">
        {/* Center Login Card (Glassmorphism Level 3) */}
        <div className="w-full max-w-[440px] bg-surface-container-low/60 backdrop-blur-2xl border border-surface-variant rounded-xl p-8 shadow-[0_32px_64px_rgba(0,0,0,0.5)] flex flex-col items-center">
          
          {/* Logo & Header */}
          <div className="flex flex-col items-center mb-10 w-full">
            <Logo size="xl" className="mb-6" />
            <p className="font-headline-md text-headline-md text-on-surface-variant tracking-wide">Decode. Detect. Defend.</p>
          </div>

          {/* General Error Alert */}
          {generalError && (
            <div className="w-full p-3 mb-6 bg-error-container/10 border border-error-container text-error rounded-lg text-xs font-label-mono flex items-center gap-2">
              <span className="material-symbols-outlined text-sm">error</span>
              <span>{generalError}</span>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="w-full space-y-6">
            {/* Email Field */}
            <div className="space-y-2">
              <label className="font-label-mono text-label-mono text-on-surface-variant block uppercase" htmlFor="email">
                Email Address
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline-variant text-lg">
                  mail
                </span>
                <input
                  className={`w-full bg-surface-dim border rounded-lg pl-10 pr-4 py-3 text-on-surface placeholder:text-outline-variant focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all duration-200 ${
                    emailError ? 'border-error focus:border-error' : 'border-outline-variant focus:border-primary'
                  }`}
                  id="email"
                  placeholder="admin@enterprise.local"
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (emailError) setEmailError(validateEmail(e.target.value));
                  }}
                  disabled={loading}
                />
              </div>
              {emailError && (
                <p className="text-error text-xs font-label-mono mt-1 flex items-center gap-1">
                  <span className="material-symbols-outlined text-xs">warning</span>
                  {emailError}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div className="space-y-2">
              <label className="font-label-mono text-label-mono text-on-surface-variant block uppercase" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline-variant text-lg">
                  lock
                </span>
                <input
                  className={`w-full bg-surface-dim border rounded-lg pl-10 pr-10 py-3 text-on-surface placeholder:text-outline-variant focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all duration-200 ${
                    passwordError ? 'border-error focus:border-error' : 'border-outline-variant focus:border-primary'
                  }`}
                  id="password"
                  placeholder="••••••••"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (passwordError) setPasswordError(validatePassword(e.target.value));
                  }}
                  disabled={loading}
                />
                <button
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-outline-variant hover:text-on-surface transition-colors"
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={loading}
                >
                  <span className="material-symbols-outlined text-lg">
                    {showPassword ? 'visibility_off' : 'visibility'}
                  </span>
                </button>
              </div>
              {passwordError && (
                <p className="text-error text-xs font-label-mono mt-1 flex items-center gap-1">
                  <span className="material-symbols-outlined text-xs">warning</span>
                  {passwordError}
                </p>
              )}
            </div>

            {/* Options */}
            <div className="flex items-center justify-between pt-2">
              <label className="flex items-center space-x-2 cursor-pointer group">
                <input
                  className="rounded border-outline-variant bg-surface-dim text-primary focus:ring-primary/30 w-4 h-4 cursor-pointer"
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  disabled={loading}
                />
                <span className="font-body-md text-body-md text-on-surface-variant group-hover:text-on-surface transition-colors">
                  Remember Me
                </span>
              </label>
              <button
                type="button"
                className="font-body-md text-body-md text-primary hover:text-primary-fixed transition-colors bg-transparent border-none cursor-pointer"
                onClick={() => alert('Forgot Password function is not connected to the backend yet.')}
                disabled={loading}
              >
                Forgot Password?
              </button>
            </div>

            {/* Actions */}
            <div className="pt-4 space-y-4">
              <button
                className="w-full bg-gradient-to-r from-primary-container to-[#1a65c9] text-on-primary-container font-headline-md text-[16px] py-3 rounded-lg hover:shadow-[0_0_20px_rgba(49,146,252,0.3)] transition-all duration-300 flex justify-center items-center space-x-2 group"
                type="submit"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="material-symbols-outlined text-xl animate-spin">sync</span>
                    <span>Signing In...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In</span>
                    <span className="material-symbols-outlined text-xl group-hover:translate-x-1 transition-transform">
                      arrow_forward
                    </span>
                  </>
                )}
              </button>
              <button
                className="w-full bg-transparent border border-outline-variant text-on-surface-variant hover:border-on-surface-variant hover:text-on-surface font-headline-md text-[16px] py-3 rounded-lg transition-all duration-200 flex justify-center items-center space-x-2"
                type="button"
                onClick={() => {
                  setEmail('offline@enterprise.local');
                  setPassword('offlineModePassword');
                  alert('Offline credentials prefilled. Click Sign In to connect locally.');
                }}
                disabled={loading}
              >
                <span className="material-symbols-outlined text-lg">wifi_off</span>
                <span>Local Offline Mode</span>
              </button>
            </div>
          </form>

          {/* Bottom Label */}
          <div className="mt-10 pt-6 border-t border-surface-variant w-full text-center">
            <p className="font-label-mono text-label-mono text-outline uppercase tracking-widest">
              Private • Secure • AI Powered • On-Premises
            </p>
          </div>
        </div>
      </main>

      {/* Minimal Custom Footer */}
      <footer className="relative z-10 w-full py-stack-md flex justify-center items-center">
        <p className="font-label-mono text-label-mono text-outline uppercase tracking-widest text-center">
          Version v1.0 | Powered by Kyptic AI Security Platform
        </p>
      </footer>
    </div>
  );
};

export default Login;
