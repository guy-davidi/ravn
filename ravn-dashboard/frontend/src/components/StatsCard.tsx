'use client';

import React from 'react';
import { LucideIcon } from 'lucide-react';
import { motion } from 'framer-motion';

interface StatsCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  color?: 'blue' | 'green' | 'red' | 'yellow' | 'purple';
  delay?: number;
}

const colorClasses = {
  blue: 'bg-blue-500/10 text-blue-600 border-blue-200',
  green: 'bg-green-500/10 text-green-600 border-green-200',
  red: 'bg-red-500/10 text-red-600 border-red-200',
  yellow: 'bg-yellow-500/10 text-yellow-600 border-yellow-200',
  purple: 'bg-purple-500/10 text-purple-600 border-purple-200',
};

export const StatsCard: React.FC<StatsCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  color = 'blue',
  delay = 0
}) => {
  const colorClass = colorClasses[color];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      className={`p-6 rounded-lg border ${colorClass} hover:shadow-lg transition-all duration-300`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium opacity-80">{title}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
          {trend && (
            <div className={`flex items-center mt-2 text-xs ${
              trend.isPositive ? 'text-green-600' : 'text-red-600'
            }`}>
              <span className="mr-1">
                {trend.isPositive ? '↗' : '↘'}
              </span>
              {Math.abs(trend.value)}%
            </div>
          )}
        </div>
        <div className={`p-3 rounded-full ${colorClass}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </motion.div>
  );
};
