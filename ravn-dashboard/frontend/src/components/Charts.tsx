'use client';

import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { SystemStats } from '@/types';

interface ChartsProps {
  stats: SystemStats;
  eventHistory: Array<{ timestamp: number; events: number }>;
  threatHistory: Array<{ timestamp: number; score: number }>;
}

const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

export const EventRateChart: React.FC<{ data: Array<{ timestamp: number; events: number }> }> = ({ data }) => {
  const chartData = data.map(item => ({
    time: new Date(item.timestamp * 1000).toLocaleTimeString(),
    events: item.events
  }));

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
        Events Per Second
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
          <XAxis dataKey="time" className="text-xs" />
          <YAxis className="text-xs" />
          <Tooltip />
          <Line 
            type="monotone" 
            dataKey="events" 
            stroke="#3B82F6" 
            strokeWidth={2}
            dot={{ fill: '#3B82F6', strokeWidth: 2, r: 4 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export const ThreatScoreChart: React.FC<{ data: Array<{ timestamp: number; score: number }> }> = ({ data }) => {
  const chartData = data.map(item => ({
    time: new Date(item.timestamp * 1000).toLocaleTimeString(),
    score: Math.round(item.score * 100)
  }));

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
        Threat Score Trend
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
          <XAxis dataKey="time" className="text-xs" />
          <YAxis domain={[0, 100]} className="text-xs" />
          <Tooltip formatter={(value) => [`${value}%`, 'Threat Score']} />
          <Line 
            type="monotone" 
            dataKey="score" 
            stroke="#EF4444" 
            strokeWidth={2}
            dot={{ fill: '#EF4444', strokeWidth: 2, r: 4 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export const EventTypeDistribution: React.FC<{ stats: SystemStats }> = ({ stats }) => {
  const data = [
    { name: 'Memory', value: stats.memory_events, color: '#3B82F6' },
    { name: 'Process', value: stats.process_events, color: '#10B981' },
    { name: 'Kernel', value: stats.kernel_events, color: '#8B5CF6' },
    { name: 'Performance', value: stats.performance_events, color: '#F59E0B' },
  ].filter(item => item.value > 0);

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
        Event Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export const SystemOverviewChart: React.FC<{ stats: SystemStats }> = ({ stats }) => {
  const data = [
    { name: 'Total Events', value: stats.total_events },
    { name: 'Memory Events', value: stats.memory_events },
    { name: 'Process Events', value: stats.process_events },
    { name: 'Kernel Events', value: stats.kernel_events },
    { name: 'Performance Events', value: stats.performance_events },
    { name: 'AI Analyses', value: stats.ai_analyses },
  ];

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
        System Overview
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
          <XAxis dataKey="name" className="text-xs" angle={-45} textAnchor="end" height={60} />
          <YAxis className="text-xs" />
          <Tooltip />
          <Bar dataKey="value" fill="#3B82F6" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
