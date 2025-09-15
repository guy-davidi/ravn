'use client';

import React, { useState, useEffect } from 'react';
import { EventData } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import { format } from 'date-fns';
import { 
  MemoryStick, 
  Cpu, 
  HardDrive, 
  Activity,
  Clock,
  User
} from 'lucide-react';

interface EventStreamProps {
  events: EventData[];
  maxItems?: number;
}

const getEventIcon = (type: string) => {
  switch (type) {
    case 'memory':
      return <MemoryStick className="w-4 h-4" />;
    case 'process':
      return <User className="w-4 h-4" />;
    case 'kernel':
      return <Cpu className="w-4 h-4" />;
    case 'performance':
      return <Activity className="w-4 h-4" />;
    default:
      return <HardDrive className="w-4 h-4" />;
  }
};

const getEventColor = (type: string) => {
  switch (type) {
    case 'memory':
      return 'bg-blue-500/10 text-blue-600 border-blue-200';
    case 'process':
      return 'bg-green-500/10 text-green-600 border-green-200';
    case 'kernel':
      return 'bg-purple-500/10 text-purple-600 border-purple-200';
    case 'performance':
      return 'bg-yellow-500/10 text-yellow-600 border-yellow-200';
    default:
      return 'bg-gray-500/10 text-gray-600 border-gray-200';
  }
};

export const EventStream: React.FC<EventStreamProps> = ({ 
  events, 
  maxItems = 50 
}) => {
  const [displayedEvents, setDisplayedEvents] = useState<EventData[]>([]);

  useEffect(() => {
    setDisplayedEvents(events.slice(0, maxItems));
  }, [events, maxItems]);

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4 h-96 overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Live Event Stream
        </h3>
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          {events.length} events
        </div>
      </div>
      
      <div className="h-80 overflow-y-auto custom-scrollbar">
        <AnimatePresence>
          {displayedEvents.map((event, index) => (
            <motion.div
              key={`${event.timestamp}-${index}`}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
              className={`mb-3 p-3 rounded-lg border ${getEventColor(event.type)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  {getEventIcon(event.type)}
                  <div>
                    <div className="font-medium capitalize">
                      {event.type} Event
                    </div>
                    <div className="text-xs opacity-75 mt-1">
                      {event.data.event_type || 'Unknown'}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-xs opacity-75">
                  <Clock className="w-3 h-3" />
                  {format(new Date(event.timestamp * 1000), 'HH:mm:ss')}
                </div>
              </div>
              
              {event.data.pid && (
                <div className="mt-2 text-xs opacity-75">
                  PID: {event.data.pid}
                </div>
              )}
              
              {event.data.filename && (
                <div className="mt-1 text-xs opacity-75 truncate">
                  File: {event.data.filename}
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
        
        {displayedEvents.length === 0 && (
          <div className="flex items-center justify-center h-full text-gray-500">
            <div className="text-center">
              <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No events detected yet</p>
              <p className="text-sm">Waiting for eBPF data...</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
