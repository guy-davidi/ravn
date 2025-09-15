export interface EventData {
  timestamp: number;
  type: string;
  data: Record<string, any>;
  source: string;
}

export interface AIAnalysis {
  timestamp: number;
  threat_score: number;
  analysis_type: string;
  details: Record<string, any>;
  recommendations: string[];
}

export interface SystemStats {
  total_events: number;
  events_per_second: number;
  memory_events: number;
  process_events: number;
  kernel_events: number;
  performance_events: number;
  ai_analyses: number;
  avg_threat_score: number;
}