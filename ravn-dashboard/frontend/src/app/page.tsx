'use client';

import React, { useState, useEffect } from 'react';
import { SystemStats, EventData, AIAnalysis } from '@/types';

const API_BASE = 'http://localhost:8000/api';
const WS_URL = 'ws://localhost:8000/ws';

export default function Dashboard() {
  const [stats, setStats] = useState<SystemStats>({
    total_events: 0,
    events_per_second: 0,
    memory_events: 0,
    process_events: 0,
    kernel_events: 0,
    performance_events: 0,
    ai_analyses: 0,
    avg_threat_score: 0
  });
  
  const [events, setEvents] = useState<EventData[]>([]);
  const [analyses, setAnalyses] = useState<AIAnalysis[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'Connecting' | 'Open' | 'Closed'>('Connecting');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isDarkMode, setIsDarkMode] = useState(true); // Default to dark mode

  // WebSocket connection
  useEffect(() => {
    let ws: WebSocket;
    let reconnectTimeout: NodeJS.Timeout;
    
    const connect = () => {
      try {
        ws = new WebSocket(WS_URL);
        
        ws.onopen = () => {
          console.log('WebSocket connected');
          setConnectionStatus('Open');
        };

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            switch (message.type) {
              case 'stats':
                setStats(message.data);
                break;
              case 'new_event':
                setEvents(prev => [message.data, ...(prev || []).slice(0, 49)]);
                break;
              case 'new_analysis':
                setAnalyses(prev => [message.data, ...(prev || []).slice(0, 19)]);
                break;
            }
          } catch (error) {
            console.error('Error parsing WebSocket message:', error);
          }
        };

        ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason);
          setConnectionStatus('Closed');
          
          // Reconnect after 3 seconds if not a normal closure
          if (event.code !== 1000) {
            reconnectTimeout = setTimeout(() => {
              console.log('Attempting to reconnect...');
              setConnectionStatus('Connecting');
              connect();
            }, 3000);
          }
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          setConnectionStatus('Closed');
        };
      } catch (error) {
        console.error('Error creating WebSocket:', error);
        setConnectionStatus('Closed');
      }
    };

    connect();

    return () => {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
      if (ws) {
        ws.close(1000, 'Component unmounting');
      }
    };
  }, []);

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, eventsRes, analysesRes] = await Promise.all([
          fetch(`${API_BASE}/stats`),
          fetch(`${API_BASE}/events/recent?limit=50`),
          fetch(`${API_BASE}/ai/analyses?limit=20`)
        ]);

        if (statsRes.ok) {
          const statsData = await statsRes.json();
          setStats(statsData);
        }

        if (eventsRes.ok) {
          const eventsData = await eventsRes.json();
          setEvents(Array.isArray(eventsData) ? eventsData : []);
        }

        if (analysesRes.ok) {
          const analysesData = await analysesRes.json();
          setAnalyses(Array.isArray(analysesData) ? analysesData : []);
        }

        setIsLoading(false);
      } catch (error) {
        console.error('Error fetching data:', error);
        setError('Failed to connect to backend API');
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const getThreatColor = (score: number) => {
    if (score >= 0.8) return 'text-red-600 bg-red-100';
    if (score >= 0.6) return 'text-orange-600 bg-orange-100';
    if (score >= 0.3) return 'text-yellow-600 bg-yellow-100';
    return 'text-green-600 bg-green-100';
  };

  const getThreatLevel = (score: number) => {
    if (score >= 0.8) return 'CRITICAL';
    if (score >= 0.6) return 'HIGH';
    if (score >= 0.3) return 'MEDIUM';
    return 'LOW';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 mx-auto mb-4"></div>
          <h2 className="text-2xl font-bold text-gray-800 mb-2">Loading RAVN Dashboard</h2>
          <p className="text-gray-600">Connecting to eBPF monitoring system...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center bg-white p-8 rounded-lg shadow-lg">
          <div className="text-red-500 text-6xl mb-4">⚠️</div>
          <h2 className="text-2xl font-bold text-gray-800 mb-2">Connection Error</h2>
          <p className="text-gray-600 mb-4">{error}</p>
          <p className="text-sm text-gray-500">Make sure the RAVN daemon and backend are running</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen transition-colors duration-300 ${isDarkMode ? 'bg-gray-900' : 'bg-gray-100'}`}>
      {/* Header */}
      <header className={`shadow-lg border-b-4 border-blue-600 transition-colors duration-300 ${
        isDarkMode ? 'bg-gray-800' : 'bg-white'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white text-2xl font-bold">R</span>
              </div>
              <div>
                <h1 className={`text-3xl font-bold transition-colors duration-300 ${
                  isDarkMode ? 'text-white' : 'text-gray-900'
                }`}>
                  RAVN Security Dashboard
                </h1>
                <p className={`text-lg transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>
                  Real-time eBPF monitoring and AI threat analysis
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Dark Mode Toggle */}
              <button
                onClick={() => setIsDarkMode(!isDarkMode)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-300 ${
                  isDarkMode ? 'bg-blue-600' : 'bg-gray-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform duration-300 ${
                    isDarkMode ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
              <span className={`text-sm font-medium transition-colors duration-300 ${
                isDarkMode ? 'text-gray-300' : 'text-gray-600'
              }`}>
                {isDarkMode ? '🌙' : '☀️'}
              </span>
              
              <div className={`px-4 py-2 rounded-full text-sm font-medium ${
                connectionStatus === 'Open' 
                  ? (isDarkMode ? 'bg-green-900 text-green-300' : 'bg-green-100 text-green-800')
                  : (isDarkMode ? 'bg-red-900 text-red-300' : 'bg-red-100 text-red-800')
              }`}>
                {connectionStatus === 'Open' ? '🟢 Connected' : '🔴 Disconnected'}
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className={`rounded-lg shadow-lg p-6 border-l-4 border-blue-500 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Total Events</p>
                <p className={`text-3xl font-bold transition-colors duration-300 ${
                  isDarkMode ? 'text-white' : 'text-gray-900'
                }`}>{stats.total_events.toLocaleString()}</p>
              </div>
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 ${
                isDarkMode ? 'bg-blue-600' : 'bg-blue-100'
              }`}>
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`rounded-lg shadow-lg p-6 border-l-4 border-green-500 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Events/sec</p>
                <p className={`text-3xl font-bold transition-colors duration-300 ${
                  isDarkMode ? 'text-white' : 'text-gray-900'
                }`}>{stats.events_per_second.toFixed(2)}</p>
              </div>
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 ${
                isDarkMode ? 'bg-green-600' : 'bg-green-100'
              }`}>
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`rounded-lg shadow-lg p-6 border-l-4 border-purple-500 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>AI Analyses</p>
                <p className={`text-3xl font-bold transition-colors duration-300 ${
                  isDarkMode ? 'text-white' : 'text-gray-900'
                }`}>{stats.ai_analyses.toLocaleString()}</p>
              </div>
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 ${
                isDarkMode ? 'bg-purple-600' : 'bg-purple-100'
              }`}>
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`rounded-lg shadow-lg p-6 border-l-4 border-red-500 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Avg Threat Score</p>
                <p className={`text-3xl font-bold transition-colors duration-300 ${
                  isDarkMode ? 'text-white' : 'text-gray-900'
                }`}>{Math.round(stats.avg_threat_score * 100)}%</p>
              </div>
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center transition-colors duration-300 ${
                isDarkMode ? 'bg-red-600' : 'bg-red-100'
              }`}>
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Event Type Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className={`rounded-lg shadow-lg p-6 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Memory Events</p>
                <p className="text-2xl font-bold text-blue-600">{stats.memory_events.toLocaleString()}</p>
              </div>
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                isDarkMode ? 'bg-blue-600' : 'bg-blue-100'
              }`}>
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`rounded-lg shadow-lg p-6 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Process Events</p>
                <p className="text-2xl font-bold text-green-600">{stats.process_events.toLocaleString()}</p>
              </div>
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                isDarkMode ? 'bg-green-600' : 'bg-green-100'
              }`}>
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`rounded-lg shadow-lg p-6 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Kernel Events</p>
                <p className="text-2xl font-bold text-purple-600">{stats.kernel_events.toLocaleString()}</p>
              </div>
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                isDarkMode ? 'bg-purple-600' : 'bg-purple-100'
              }`}>
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`rounded-lg shadow-lg p-6 transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>Performance Events</p>
                <p className="text-2xl font-bold text-yellow-600">{stats.performance_events.toLocaleString()}</p>
              </div>
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                isDarkMode ? 'bg-yellow-600' : 'bg-yellow-100'
              }`}>
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Live Data Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Events */}
          <div className={`rounded-lg shadow-lg transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className={`px-6 py-4 border-b transition-colors duration-300 ${
              isDarkMode ? 'border-gray-700' : 'border-gray-200'
            }`}>
              <h3 className={`text-xl font-bold flex items-center gap-2 transition-colors duration-300 ${
                isDarkMode ? 'text-white' : 'text-gray-900'
              }`}>
                <div className={`w-6 h-6 rounded flex items-center justify-center ${
                  isDarkMode ? 'bg-blue-600' : 'bg-blue-100'
                }`}>
                  <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 4V2a1 1 0 011-1h8a1 1 0 011 1v2m-9 0h10m-10 0a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V6a2 2 0 00-2-2M9 8h6m-6 4h6m-6 4h6" />
                  </svg>
                </div>
                Live Event Stream
              </h3>
            </div>
            <div className="p-6 max-h-96 overflow-y-auto">
              {events && events.length > 0 ? (
                <div className="space-y-3">
                  {events.slice(0, 10).map((event, index) => (
                    <div key={index} className={`flex items-center justify-between p-3 rounded-lg transition-colors duration-300 ${
                      isDarkMode ? 'bg-gray-700' : 'bg-gray-50'
                    }`}>
                      <div className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                          event.type === 'memory' ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100') :
                          event.type === 'process' ? (isDarkMode ? 'bg-green-600' : 'bg-green-100') :
                          event.type === 'kernel' ? (isDarkMode ? 'bg-purple-600' : 'bg-purple-100') :
                          (isDarkMode ? 'bg-yellow-600' : 'bg-yellow-100')
                        }`}>
                          <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        </div>
                        <div>
                          <p className={`font-medium capitalize transition-colors duration-300 ${
                            isDarkMode ? 'text-white' : 'text-gray-900'
                          }`}>{event.type || 'Unknown'} Event</p>
                          <p className={`text-sm transition-colors duration-300 ${
                            isDarkMode ? 'text-gray-300' : 'text-gray-600'
                          }`}>
                            {event.data?.event_type || 'Unknown'}
                          </p>
                        </div>
                      </div>
                      <div className={`text-sm transition-colors duration-300 ${
                        isDarkMode ? 'text-gray-400' : 'text-gray-500'
                      }`}>
                        {event.timestamp ? new Date(event.timestamp * 1000).toLocaleTimeString() : 'Unknown time'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className={`text-center py-8 transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-400' : 'text-gray-500'
                }`}>
                  <div className={`w-16 h-16 mx-auto mb-4 rounded-full flex items-center justify-center ${
                    isDarkMode ? 'bg-gray-700' : 'bg-gray-200'
                  }`}>
                    <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p>No events detected yet</p>
                  <p className="text-sm">Waiting for eBPF data...</p>
                </div>
              )}
            </div>
          </div>

          {/* AI Analysis Log */}
          <div className={`rounded-lg shadow-lg transition-colors duration-300 ${
            isDarkMode ? 'bg-gray-800' : 'bg-white'
          }`}>
            <div className={`px-6 py-4 border-b transition-colors duration-300 ${
              isDarkMode ? 'border-gray-700' : 'border-gray-200'
            }`}>
              <h3 className={`text-xl font-bold flex items-center gap-2 transition-colors duration-300 ${
                isDarkMode ? 'text-white' : 'text-gray-900'
              }`}>
                <div className={`w-6 h-6 rounded flex items-center justify-center ${
                  isDarkMode ? 'bg-purple-600' : 'bg-purple-100'
                }`}>
                  <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                </div>
                AI Analysis Log
              </h3>
            </div>
            <div className="p-6 max-h-96 overflow-y-auto">
              {analyses && analyses.length > 0 ? (
                <div className="space-y-3">
                  {analyses.slice(0, 10).map((analysis, index) => (
                    <div key={index} className={`p-4 rounded-lg transition-colors duration-300 ${
                      isDarkMode ? 'bg-gray-700' : 'bg-gray-50'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <div className={`w-6 h-6 rounded flex items-center justify-center ${
                            isDarkMode ? 'bg-purple-600' : 'bg-purple-100'
                          }`}>
                            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                            </svg>
                          </div>
                          <span className={`font-medium capitalize transition-colors duration-300 ${
                            isDarkMode ? 'text-white' : 'text-gray-900'
                          }`}>
                            {analysis.analysis_type ? analysis.analysis_type.replace(/_/g, ' ') : 'Unknown Analysis'}
                          </span>
                        </div>
                        <div className={`px-3 py-1 rounded-full text-sm font-medium ${getThreatColor(analysis.threat_score || 0)}`}>
                          {getThreatLevel(analysis.threat_score || 0)} ({Math.round((analysis.threat_score || 0) * 100)}%)
                        </div>
                      </div>
                      <div className={`text-sm transition-colors duration-300 ${
                        isDarkMode ? 'text-gray-300' : 'text-gray-600'
                      }`}>
                        {analysis.timestamp ? new Date(analysis.timestamp * 1000).toLocaleString() : 'Unknown time'}
                      </div>
                      {analysis.recommendations && analysis.recommendations.length > 0 && (
                        <div className="mt-2">
                          <p className={`text-sm font-medium transition-colors duration-300 ${
                            isDarkMode ? 'text-gray-200' : 'text-gray-700'
                          }`}>Recommendations:</p>
                          <ul className={`text-sm mt-1 transition-colors duration-300 ${
                            isDarkMode ? 'text-gray-300' : 'text-gray-600'
                          }`}>
                            {analysis.recommendations.slice(0, 2).map((rec, recIndex) => (
                              <li key={recIndex} className="flex items-start gap-2">
                                <span className="text-green-500">✓</span>
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className={`text-center py-8 transition-colors duration-300 ${
                  isDarkMode ? 'text-gray-400' : 'text-gray-500'
                }`}>
                  <div className={`w-16 h-16 mx-auto mb-4 rounded-full flex items-center justify-center ${
                    isDarkMode ? 'bg-gray-700' : 'bg-gray-200'
                  }`}>
                    <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                    </svg>
                  </div>
                  <p>No AI analyses yet</p>
                  <p className="text-sm">Waiting for AI processing...</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}