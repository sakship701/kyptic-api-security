import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import Logo from '../../components/ui/Logo';
import loginBg from '../../assets/login-bg.png';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login, register } = useApp();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // Validation & Error States
  const [loading, setLoading] = useState(false);
  const [fullNameError, setFullNameError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [confirmPasswordError, setConfirmPasswordError] = useState<string | null>(null);
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
    if (val.length < 8) {
      return 'Password must be at least 8 characters';
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFullNameError(null);
    setEmailError(null);
    setPasswordError(null);
    setConfirmPasswordError(null);
    setGeneralError(null);

    const emailErr = validateEmail(email);
    const passErr = validatePassword(password);
    let hasError = false;

    if (emailErr) {
      setEmailError(emailErr);
      hasError = true;
    }
    if (passErr) {
      setPasswordError(passErr);
      hasError = true;
    }

    if (mode === 'register') {
      if (!fullName.trim()) {
        setFullNameError('Full name is required');
        hasError = true;
      }
      if (password !== confirmPassword) {
        setConfirmPasswordError('Passwords do not match');
        hasError = true;
      }
    }

    if (hasError) return;

    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        await register(email, password, fullName);
      }
      navigate('/dashboard');
    } catch (err) {
      setGeneralError(err instanceof Error ? err.message : 'Authentication failed. Please check your credentials.');
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
        {/* Center Login Card */}
        <div className="w-full max-w-[460px] bg-surface-container-low/80 backdrop-blur-2xl border border-surface-variant rounded-xl p-8 shadow-[0_32px_64px_rgba(0,0,0,0.5)] flex flex-col items-center">
          
          {/* Logo & Header */}
          <div className="flex flex-col items-center mb-6 w-full">
            <Logo size="xl" className="mb-4" />
            <p className="font-headline-md text-headline-md text-on-surface-variant tracking-wide">Decode. Detect. Defend.</p>
          </div>

          {/* Mode Switcher Tabs */}
          <div className="w-full flex rounded-lg bg-surface-dim p-1 mb-6 border border-surface-variant">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setGeneralError(null);
              }}
              className={`flex-1 py-2 text-sm font-headline-md rounded-md transition-all duration-200 ${
                mode === 'login'
                  ? 'bg-primary-container text-on-primary-container shadow'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setGeneralError(null);
              }}
              className={`flex-1 py-2 text-sm font-headline-md rounded-md transition-all duration-200 ${
                mode === 'register'
                  ? 'bg-primary-container text-on-primary-container shadow'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              Create Account
            </button>
          </div>

          {/* General Error Alert */}
          {generalError && (
            <div className="w-full p-3 mb-6 bg-error-container/10 border border-error-container text-error rounded-lg text-xs font-label-mono flex items-center gap-2">
              <span className="material-symbols-outlined text-sm">error</span>
              <span>{generalError}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="w-full space-y-4">
            {/* Full Name Field (Register Mode Only) */}
            {mode === 'register' && (
              <div className="space-y-1">
                <label className="font-label-mono text-xs text-on-surface-variant block uppercase" htmlFor="fullName">
                  Full Name
                </label>
                <div className="relative">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline-variant text-lg">
                    person
                  </span>
                  <input
                    className={`w-full bg-surface-dim border rounded-lg pl-10 pr-4 py-2.5 text-on-surface placeholder:text-outline-variant focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all ${
                      fullNameError ? 'border-error focus:border-error' : 'border-outline-variant focus:border-primary'
                    }`}
                    id="fullName"
                    placeholder="Alex Morgan"
                    type="text"
                    value={fullName}
                    onChange={(e) => {
                      setFullName(e.target.value);
                      if (fullNameError) setFullNameError(null);
                    }}
                    disabled={loading}
                  />
                </div>
                {fullNameError && (
                  <p className="text-error text-xs font-label-mono mt-1 flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">warning</span>
                    {fullNameError}
                  </p>
                )}
              </div>
            )}

            {/* Email Field */}
            <div className="space-y-1">
              <label className="font-label-mono text-xs text-on-surface-variant block uppercase" htmlFor="email">
                Email Address
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline-variant text-lg">
                  mail
                </span>
                <input
                  className={`w-full bg-surface-dim border rounded-lg pl-10 pr-4 py-2.5 text-on-surface placeholder:text-outline-variant focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all ${
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
            <div className="space-y-1">
              <label className="font-label-mono text-xs text-on-surface-variant block uppercase" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline-variant text-lg">
                  lock
                </span>
                <input
                  className={`w-full bg-surface-dim border rounded-lg pl-10 pr-10 py-2.5 text-on-surface placeholder:text-outline-variant focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all ${
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

            {/* Confirm Password Field (Register Mode Only) */}
            {mode === 'register' && (
              <div className="space-y-1">
                <label className="font-label-mono text-xs text-on-surface-variant block uppercase" htmlFor="confirmPassword">
                  Confirm Password
                </label>
                <div className="relative">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline-variant text-lg">
                    lock_reset
                  </span>
                  <input
                    className={`w-full bg-surface-dim border rounded-lg pl-10 pr-4 py-2.5 text-on-surface placeholder:text-outline-variant focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all ${
                      confirmPasswordError ? 'border-error focus:border-error' : 'border-outline-variant focus:border-primary'
                    }`}
                    id="confirmPassword"
                    placeholder="••••••••"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value);
                      if (confirmPasswordError) setConfirmPasswordError(null);
                    }}
                    disabled={loading}
                  />
                </div>
                {confirmPasswordError && (
                  <p className="text-error text-xs font-label-mono mt-1 flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">warning</span>
                    {confirmPasswordError}
                  </p>
                )}
              </div>
            )}

            {/* Submit Action */}
            <div className="pt-2">
              <button
                className="w-full bg-gradient-to-r from-primary-container to-[#1a65c9] text-on-primary-container font-headline-md text-[16px] py-3 rounded-lg hover:shadow-[0_0_20px_rgba(49,146,252,0.3)] transition-all duration-300 flex justify-center items-center space-x-2 group cursor-pointer"
                type="submit"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="material-symbols-outlined text-xl animate-spin">sync</span>
                    <span>{mode === 'login' ? 'Signing In...' : 'Creating Account...'}</span>
                  </>
                ) : (
                  <>
                    <span>{mode === 'login' ? 'Sign In' : 'Create Account'}</span>
                    <span className="material-symbols-outlined text-xl group-hover:translate-x-1 transition-transform">
                      arrow_forward
                    </span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Bottom Label */}
          <div className="mt-8 pt-4 border-t border-surface-variant w-full text-center">
            <p className="font-label-mono text-label-mono text-outline uppercase tracking-widest">
              Private • Secure • AI Powered • On-Premises
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 w-full py-stack-md flex justify-center items-center">
        <p className="font-label-mono text-label-mono text-outline uppercase tracking-widest text-center">
          Version v1.0 | Powered by Kyptic AI Security Platform
        </p>
      </footer>
    </div>
  );
};

export default Login;
