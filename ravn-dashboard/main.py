#!/usr/bin/env python3
"""
RAVN Dashboard - FastAPI Backend
Real-time eBPF monitoring and AI analysis dashboard
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import redis.asyncio as redis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Redis connection
redis_client: Optional[redis.Redis] = None

# FastAPI app definition
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Redis connection and start background tasks"""
    logger.info("Starting RAVN Dashboard API...")
    await get_redis()
    asyncio.create_task(redis_monitor())
    logger.info("RAVN Dashboard API started successfully")
    
    yield
    
    # Cleanup on shutdown
    global redis_client
    if redis_client:
        await redis_client.close()
    logger.info("RAVN Dashboard API shutdown")

# Create FastAPI app with lifespan
app = FastAPI(title="RAVN Dashboard API", version="1.0.0", lifespan=lifespan)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if self.active_connections:
            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception as e:
                    # Log the specific error for debugging
                    logger.debug(f"WebSocket send error: {e}")
                    disconnected.append(connection)
            
            # Remove disconnected connections
            for conn in disconnected:
                self.disconnect(conn)

manager = ConnectionManager()

# Pydantic models
class EventData(BaseModel):
    timestamp: float
    event_type: str
    data: Dict[str, Any]
    source: str

class AIAnalysis(BaseModel):
    timestamp: float
    threat_score: float
    analysis_type: str
    details: Dict[str, Any]
    recommendations: List[str]

class SystemStats(BaseModel):
    total_events: int
    events_per_second: float
    memory_events: int
    process_events: int
    kernel_events: int
    performance_events: int
    ai_analyses: int
    avg_threat_score: float

# Redis connection dependency
async def get_redis():
    global redis_client
    if redis_client is None:
        redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    return redis_client

# API Routes
@app.get("/")
async def root():
    return {"message": "RAVN Dashboard API", "status": "running"}

@app.get("/api/health")
async def health_check():
    try:
        redis_conn = await get_redis()
        await redis_conn.ping()
        return {"status": "healthy", "redis": "connected", "timestamp": time.time()}
    except Exception as e:
        return {"status": "unhealthy", "redis": "disconnected", "error": str(e)}

@app.get("/api/events/recent")
async def get_recent_events(limit: int = 100):
    """Get recent eBPF events from Redis"""
    try:
        redis_conn = await get_redis()
        
        # Get recent events from different streams
        events = []
        
        # Memory events
        memory_events = await redis_conn.lrange("ravn:events:memory", 0, limit-1)
        for event in memory_events:
            try:
                event_data = json.loads(event)
                events.append({
                    "timestamp": event_data.get("timestamp", time.time()),
                    "type": "memory",
                    "data": event_data,
                    "source": "eBPF"
                })
            except:
                continue
        
        # Process events
        process_events = await redis_conn.lrange("ravn:events:process", 0, limit-1)
        for event in process_events:
            try:
                event_data = json.loads(event)
                events.append({
                    "timestamp": event_data.get("timestamp", time.time()),
                    "type": "process",
                    "data": event_data,
                    "source": "eBPF"
                })
            except:
                continue
        
        # Kernel events
        kernel_events = await redis_conn.lrange("ravn:events:kernel", 0, limit-1)
        for event in kernel_events:
            try:
                event_data = json.loads(event)
                events.append({
                    "timestamp": event_data.get("timestamp", time.time()),
                    "type": "kernel",
                    "data": event_data,
                    "source": "eBPF"
                })
            except:
                continue
        
        # Performance events
        perf_events = await redis_conn.lrange("ravn:events:performance", 0, limit-1)
        for event in perf_events:
            try:
                event_data = json.loads(event)
                events.append({
                    "timestamp": event_data.get("timestamp", time.time()),
                    "type": "performance",
                    "data": event_data,
                    "source": "eBPF"
                })
            except:
                continue
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events[:limit]
        
    except Exception as e:
        logger.error(f"Error getting recent events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ai/analyses")
async def get_ai_analyses(limit: int = 50):
    """Get recent AI analyses from Redis"""
    try:
        redis_conn = await get_redis()
        
        # Get AI analysis results
        analyses = await redis_conn.lrange("ravn:ai:analyses", 0, limit-1)
        results = []
        
        for analysis in analyses:
            try:
                analysis_data = json.loads(analysis)
                results.append({
                    "timestamp": analysis_data.get("timestamp", time.time()),
                    "threat_score": analysis_data.get("threat_score", 0.0),
                    "analysis_type": analysis_data.get("analysis_type", "unknown"),
                    "details": analysis_data.get("details", {}),
                    "recommendations": analysis_data.get("recommendations", [])
                })
            except:
                continue
        
        # Sort by timestamp (newest first)
        results.sort(key=lambda x: x["timestamp"], reverse=True)
        return results[:limit]
        
    except Exception as e:
        logger.error(f"Error getting AI analyses: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def get_system_stats():
    """Get system statistics"""
    try:
        redis_conn = await get_redis()
        
        # Debug: Check what keys exist in Redis
        all_keys = await redis_conn.keys("*")
        logger.info(f"Redis keys found: {all_keys}")
        
        # Get event counts
        memory_count = await redis_conn.llen("ravn:events:memory")
        process_count = await redis_conn.llen("ravn:events:process")
        kernel_count = await redis_conn.llen("ravn:events:kernel")
        perf_count = await redis_conn.llen("ravn:events:performance")
        ai_count = await redis_conn.llen("ravn:ai:analyses")
        
        logger.info(f"Event counts - Memory: {memory_count}, Process: {process_count}, Kernel: {kernel_count}, Performance: {perf_count}, AI: {ai_count}")
        
        total_events = memory_count + process_count + kernel_count + perf_count
        
        # Calculate average threat score
        analyses = await redis_conn.lrange("ravn:ai:analyses", 0, 99)  # Last 100
        threat_scores = []
        for analysis in analyses:
            try:
                data = json.loads(analysis)
                if "threat_score" in data:
                    threat_scores.append(float(data["threat_score"]))
            except:
                continue
        
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
        
        # Calculate events per second (rough estimate)
        events_per_second = 0.0
        if total_events > 0:
            # Get timestamp of oldest event
            oldest_timestamp = time.time()
            for key in ["ravn:events:memory", "ravn:events:process", "ravn:events:kernel", "ravn:events:performance"]:
                events = await redis_conn.lrange(key, -1, -1)  # Get oldest
                if events:
                    try:
                        event_data = json.loads(events[0])
                        if "timestamp" in event_data:
                            oldest_timestamp = min(oldest_timestamp, event_data["timestamp"])
                    except:
                        continue
            
            time_span = time.time() - oldest_timestamp
            if time_span > 0:
                events_per_second = total_events / time_span
        
        return SystemStats(
            total_events=total_events,
            events_per_second=events_per_second,
            memory_events=memory_count,
            process_events=process_count,
            kernel_events=kernel_count,
            performance_events=perf_count,
            ai_analyses=ai_count,
            avg_threat_score=avg_threat_score
        )
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send periodic updates
            await asyncio.sleep(1)
            
            # Send system stats
            try:
                stats = await get_system_stats()
                await websocket.send_text(json.dumps({
                    "type": "stats",
                    "data": stats.dict(),
                    "timestamp": time.time()
                }))
            except WebSocketDisconnect:
                # Client disconnected, break the loop
                break
            except Exception as e:
                # Log other errors but don't spam
                logger.debug(f"Error sending stats: {e}")
                break
                
    except WebSocketDisconnect:
        pass  # Client disconnected normally
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

# Background task to monitor Redis and broadcast updates
async def redis_monitor():
    """Monitor Redis for new events and broadcast to WebSocket clients"""
    redis_conn = await get_redis()
    
    while True:
        try:
            # Only broadcast if there are active connections
            if not manager.active_connections:
                await asyncio.sleep(1)  # Wait longer if no connections
                continue
                
            # Check for new events in all streams
            for stream in ["ravn:events:memory", "ravn:events:process", "ravn:events:kernel", "ravn:events:performance"]:
                # Get latest event
                events = await redis_conn.lrange(stream, 0, 0)
                if events:
                    try:
                        event_data = json.loads(events[0])
                        await manager.broadcast({
                            "type": "new_event",
                            "stream": stream.split(":")[-1],
                            "data": event_data,
                            "timestamp": time.time()
                        })
                    except Exception as e:
                        logger.debug(f"Error processing event from {stream}: {e}")
                        continue
            
            # Check for new AI analyses
            analyses = await redis_conn.lrange("ravn:ai:analyses", 0, 0)
            if analyses:
                try:
                    analysis_data = json.loads(analyses[0])
                    await manager.broadcast({
                        "type": "new_analysis",
                        "data": analysis_data,
                        "timestamp": time.time()
                    })
                except Exception as e:
                    logger.debug(f"Error processing AI analysis: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error in redis_monitor: {e}")
            await asyncio.sleep(5)  # Wait longer on error
        
        await asyncio.sleep(0.5)  # Check every 500ms


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
