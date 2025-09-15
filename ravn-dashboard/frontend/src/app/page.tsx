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
                setEvents(prev => [message.data, ...prev.slice(0, 49)]);
                break;
              case 'new_analysis':
                setAnalyses(prev => [message.data, ...prev.slice(0, 19)]);
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
          setEvents(eventsData);
        }

        if (analysesRes.ok) {
          const analysesData = await analysesRes.json();
          setAnalyses(analysesData);
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
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white shadow-lg border-b-4 border-blue-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white text-2xl font-bold">R</span>
              </div>
              <div>
                <h1 className="text-3xl font-bold text-gray-900">
                  RAVN Security Dashboard
                </h1>
                <p className="text-lg text-gray-600">
                  Real-time eBPF monitoring and AI threat analysis
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className={`px-4 py-2 rounded-full text-sm font-medium ${
                connectionStatus === 'Open' 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
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
          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-blue-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Events</p>
                <p className="text-3xl font-bold text-gray-900">{stats.total_events.toLocaleString()}</p>
              </div>
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                <span className="text-2xl">📊</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-green-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Events/sec</p>
                <p className="text-3xl font-bold text-gray-900">{stats.events_per_second.toFixed(2)}</p>
              </div>
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                <span className="text-2xl">⚡</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-purple-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">AI Analyses</p>
                <p className="text-3xl font-bold text-gray-900">{stats.ai_analyses.toLocaleString()}</p>
              </div>
              <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center">
                <span className="text-2xl">🧠</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-red-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Avg Threat Score</p>
                <p className="text-3xl font-bold text-gray-900">{Math.round(stats.avg_threat_score * 100)}%</p>
              </div>
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <span className="text-2xl">🛡️</span>
              </div>
            </div>
          </div>
        </div>

        {/* Event Type Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Memory Events</p>
                <p className="text-2xl font-bold text-blue-600">{stats.memory_events.toLocaleString()}</p>
              </div>
              <span className="text-3xl">💾</span>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Process Events</p>
                <p className="text-2xl font-bold text-green-600">{stats.process_events.toLocaleString()}</p>
              </div>
              <span className="text-3xl">⚙️</span>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Kernel Events</p>
                <p className="text-2xl font-bold text-purple-600">{stats.kernel_events.toLocaleString()}</p>
              </div>
              <span className="text-3xl">🔧</span>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Performance Events</p>
                <p className="text-2xl font-bold text-yellow-600">{stats.performance_events.toLocaleString()}</p>
              </div>
              <span className="text-3xl">📈</span>
            </div>
          </div>
        </div>

        {/* Live Data Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Events */}
          <div className="bg-white rounded-lg shadow-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-xl font-bold text-gray-900 flex items-center gap-2">
                <span className="text-2xl">📡</span>
                Live Event Stream
              </h3>
            </div>
            <div className="p-6 max-h-96 overflow-y-auto">
              {events.length > 0 ? (
                <div className="space-y-3">
                  {events.slice(0, 10).map((event, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">
                          {event.type === 'memory' ? '💾' : 
                           event.type === 'process' ? '⚙️' : 
                           event.type === 'kernel' ? '🔧' : '📈'}
                        </span>
                        <div>
                          <p className="font-medium text-gray-900 capitalize">{event.type} Event</p>
                          <p className="text-sm text-gray-600">
                            {event.data.event_type || 'Unknown'}
                          </p>
                        </div>
                      </div>
                      <div className="text-sm text-gray-500">
                        {new Date(event.timestamp * 1000).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <span className="text-4xl mb-2 block">⏳</span>
                  <p>No events detected yet</p>
                  <p className="text-sm">Waiting for eBPF data...</p>
                </div>
              )}
            </div>
          </div>

          {/* AI Analysis Log */}
          <div className="bg-white rounded-lg shadow-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-xl font-bold text-gray-900 flex items-center gap-2">
                <span className="text-2xl">🧠</span>
                AI Analysis Log
              </h3>
            </div>
            <div className="p-6 max-h-96 overflow-y-auto">
              {analyses.length > 0 ? (
                <div className="space-y-3">
                  {analyses.slice(0, 10).map((analysis, index) => (
                    <div key={index} className="p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-lg">🔍</span>
                          <span className="font-medium text-gray-900 capitalize">
                            {analysis.analysis_type.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <div className={`px-3 py-1 rounded-full text-sm font-medium ${getThreatColor(analysis.threat_score)}`}>
                          {getThreatLevel(analysis.threat_score)} ({Math.round(analysis.threat_score * 100)}%)
                        </div>
                      </div>
                      <div className="text-sm text-gray-600">
                        {new Date(analysis.timestamp * 1000).toLocaleString()}
                      </div>
                      {analysis.recommendations.length > 0 && (
                        <div className="mt-2">
                          <p className="text-sm font-medium text-gray-700">Recommendations:</p>
                          <ul className="text-sm text-gray-600 mt-1">
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
                <div className="text-center py-8 text-gray-500">
                  <span className="text-4xl mb-2 block">🤖</span>
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