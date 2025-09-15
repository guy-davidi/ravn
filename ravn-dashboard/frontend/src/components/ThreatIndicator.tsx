'use client';

import React from 'react';
import { ThreatLevel, ThreatIndicator as ThreatIndicatorType } from '@/types';
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck } from 'lucide-react';

interface ThreatIndicatorProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  showText?: boolean;
}

const getThreatLevel = (score: number): ThreatLevel => {
  if (score >= 0.8) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.3) return 'medium';
  return 'low';
};

const getThreatIndicator = (level: ThreatLevel): ThreatIndicatorType => {
  switch (level) {
    case 'critical':
      return {
        level: 'critical',
        score: 0,
        color: 'text-red-500',
        bgColor: 'bg-red-500/20'
      };
    case 'high':
      return {
        level: 'high',
        score: 0,
        color: 'text-orange-500',
        bgColor: 'bg-orange-500/20'
      };
    case 'medium':
      return {
        level: 'medium',
        score: 0,
        color: 'text-yellow-500',
        bgColor: 'bg-yellow-500/20'
      };
    case 'low':
      return {
        level: 'low',
        score: 0,
        color: 'text-green-500',
        bgColor: 'bg-green-500/20'
      };
  }
};

const getIcon = (level: ThreatLevel) => {
  switch (level) {
    case 'critical':
      return <AlertTriangle className="w-4 h-4" />;
    case 'high':
      return <ShieldAlert className="w-4 h-4" />;
    case 'medium':
      return <Shield className="w-4 h-4" />;
    case 'low':
      return <ShieldCheck className="w-4 h-4" />;
  }
};

const getSizeClasses = (size: 'sm' | 'md' | 'lg') => {
  switch (size) {
    case 'sm':
      return 'text-xs px-2 py-1';
    case 'md':
      return 'text-sm px-3 py-1.5';
    case 'lg':
      return 'text-base px-4 py-2';
  }
};

export const ThreatIndicator: React.FC<ThreatIndicatorProps> = ({
  score,
  size = 'md',
  showIcon = true,
  showText = true
}) => {
  const level = getThreatLevel(score);
  const indicator = getThreatIndicator(level);
  const icon = getIcon(level);
  const sizeClasses = getSizeClasses(size);

  return (
    <div className={`inline-flex items-center gap-2 rounded-full ${indicator.bgColor} ${indicator.color} ${sizeClasses} threat-${level}`}>
      {showIcon && icon}
      {showText && (
        <span className="font-medium">
          {level.toUpperCase()} ({Math.round(score * 100)}%)
        </span>
      )}
    </div>
  );
};
