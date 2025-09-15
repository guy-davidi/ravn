'use client';

import React, { useState } from 'react';
import { AIAnalysis } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import { format } from 'date-fns';
import { 
  Brain, 
  AlertTriangle, 
  CheckCircle, 
  Info,
  Clock,
  TrendingUp,
  Shield
} from 'lucide-react';
import { ThreatIndicator } from './ThreatIndicator';

interface AIAnalysisLogProps {
  analyses: AIAnalysis[];
  maxItems?: number;
}

const getAnalysisIcon = (analysisType: string) => {
  switch (analysisType.toLowerCase()) {
    case 'threat_detection':
      return <AlertTriangle className="w-4 h-4" />;
    case 'anomaly_detection':
      return <TrendingUp className="w-4 h-4" />;
    case 'behavior_analysis':
      return <Brain className="w-4 h-4" />;
    case 'security_scan':
      return <Shield className="w-4 h-4" />;
    default:
      return <Info className="w-4 h-4" />;
  }
};

const getAnalysisColor = (threatScore: number) => {
  if (threatScore >= 0.8) return 'bg-red-500/10 text-red-600 border-red-200';
  if (threatScore >= 0.6) return 'bg-orange-500/10 text-orange-600 border-orange-200';
  if (threatScore >= 0.3) return 'bg-yellow-500/10 text-yellow-600 border-yellow-200';
  return 'bg-green-500/10 text-green-600 border-green-200';
};

export const AIAnalysisLog: React.FC<AIAnalysisLogProps> = ({ 
  analyses, 
  maxItems = 20 
}) => {
  const [expandedItems, setExpandedItems] = useState<Set<number>>(new Set());

  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedItems(newExpanded);
  };

  const displayedAnalyses = analyses.slice(0, maxItems);

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4 h-96 overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
          <Brain className="w-5 h-5" />
          AI Analysis Log
        </h3>
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
          {analyses.length} analyses
        </div>
      </div>
      
      <div className="h-80 overflow-y-auto custom-scrollbar">
        <AnimatePresence>
          {displayedAnalyses.map((analysis, index) => (
            <motion.div
              key={`${analysis.timestamp}-${index}`}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
              className={`mb-3 p-3 rounded-lg border ${getAnalysisColor(analysis.threat_score)} cursor-pointer hover:shadow-md transition-all duration-200`}
              onClick={() => toggleExpanded(index)}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  {getAnalysisIcon(analysis.analysis_type)}
                  <div className="flex-1">
                    <div className="font-medium capitalize">
                      {analysis.analysis_type.replace(/_/g, ' ')}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <ThreatIndicator score={analysis.threat_score} size="sm" showText={false} />
                      <span className="text-xs opacity-75">
                        Score: {Math.round(analysis.threat_score * 100)}%
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-xs opacity-75">
                  <Clock className="w-3 h-3" />
                  {format(new Date(analysis.timestamp * 1000), 'HH:mm:ss')}
                </div>
              </div>
              
              <AnimatePresence>
                {expandedItems.has(index) && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                    className="mt-3 pt-3 border-t border-current/20"
                  >
                    <div className="space-y-2">
                      {Object.entries(analysis.details).map(([key, value]) => (
                        <div key={key} className="text-xs">
                          <span className="font-medium opacity-75">
                            {key.replace(/_/g, ' ')}:
                          </span>
                          <span className="ml-2">
                            {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                          </span>
                        </div>
                      ))}
                      
                      {analysis.recommendations.length > 0 && (
                        <div className="mt-3">
                          <div className="text-xs font-medium opacity-75 mb-1">
                            Recommendations:
                          </div>
                          <ul className="text-xs space-y-1">
                            {analysis.recommendations.map((rec, recIndex) => (
                              <li key={recIndex} className="flex items-start gap-2">
                                <CheckCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </AnimatePresence>
        
        {displayedAnalyses.length === 0 && (
          <div className="flex items-center justify-center h-full text-gray-500">
            <div className="text-center">
              <Brain className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No AI analyses yet</p>
              <p className="text-sm">Waiting for AI processing...</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
