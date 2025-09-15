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
        
        # Get recent events from the actual Redis key
        events = []
        
        # Get events from events:raw key based on data type
        events_type = await redis_conn.type("events:raw")
        raw_events = []
        
        if events_type == "list":
            raw_events = await redis_conn.lrange("events:raw", 0, limit-1)
        elif events_type == "string":
            event_data = await redis_conn.get("events:raw")
            if event_data:
                raw_events = [event_data]
        elif events_type == "set":
            raw_events = await redis_conn.smembers("events:raw")
            raw_events = list(raw_events)[:limit]
        
        for event in raw_events:
            try:
                event_data = json.loads(event)
                # Determine event type from the data
                event_type = "unknown"
                if "memory" in str(event_data).lower():
                    event_type = "memory"
                elif "process" in str(event_data).lower() or "exec" in str(event_data).lower():
                    event_type = "process"
                elif "kernel" in str(event_data).lower() or "module" in str(event_data).lower():
                    event_type = "kernel"
                elif "performance" in str(event_data).lower() or "cpu" in str(event_data).lower():
                    event_type = "performance"
                
                events.append({
                    "timestamp": event_data.get("timestamp", time.time()),
                    "type": event_type,
                    "data": event_data,
                    "source": "eBPF"
                })
            except Exception as e:
                logger.debug(f"Error parsing event: {e}")
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
        
        # Get AI analysis results from threat:current key based on data type
        threat_type = await redis_conn.type("threat:current")
        analyses = []
        
        if threat_type == "list":
            analyses = await redis_conn.lrange("threat:current", 0, limit-1)
        elif threat_type == "string":
            analysis_data = await redis_conn.get("threat:current")
            if analysis_data:
                analyses = [analysis_data]
        elif threat_type == "set":
            analyses = await redis_conn.smembers("threat:current")
            analyses = list(analyses)[:limit]
        
        results = []
        for analysis in analyses:
            try:
                analysis_data = json.loads(analysis)
                results.append({
                    "timestamp": analysis_data.get("timestamp", time.time()),
                    "threat_score": analysis_data.get("threat_score", analysis_data.get("score", 0.0)),
                    "analysis_type": analysis_data.get("analysis_type", "threat_analysis"),
                    "details": analysis_data.get("details", analysis_data),
                    "recommendations": analysis_data.get("recommendations", [])
                })
            except Exception as e:
                logger.debug(f"Error parsing AI analysis: {e}")
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
        
        # Check data types of Redis keys
        events_type = await redis_conn.type("events:raw")
        threat_type = await redis_conn.type("threat:current")
        
        logger.info(f"Redis key types - events:raw: {events_type}, threat:current: {threat_type}")
        
        # Get event counts based on data type
        events_count = 0
        threat_count = 0
        
        if events_type == "list":
            events_count = await redis_conn.llen("events:raw")
        elif events_type == "string":
            events_data = await redis_conn.get("events:raw")
            if events_data:
                events_count = 1  # Single string value
                logger.info(f"Sample event (string): {events_data}")
        elif events_type == "set":
            events_count = await redis_conn.scard("events:raw")
        
        if threat_type == "list":
            threat_count = await redis_conn.llen("threat:current")
        elif threat_type == "string":
            threat_data = await redis_conn.get("threat:current")
            if threat_data:
                threat_count = 1  # Single string value
                logger.info(f"Sample threat (string): {threat_data}")
        elif threat_type == "set":
            threat_count = await redis_conn.scard("threat:current")
        
        # Parse events to categorize by type
        memory_count = 0
        process_count = 0
        kernel_count = 0
        perf_count = 0
        
        if events_count > 0:
            # Get a sample of events to categorize
            sample_size = min(100, events_count)  # Sample up to 100 events
            if events_type == "list":
                sample_events = await redis_conn.lrange("events:raw", 0, sample_size-1)
            elif events_type == "string":
                event_data = await redis_conn.get("events:raw")
                sample_events = [event_data] if event_data else []
            elif events_type == "set":
                sample_events = await redis_conn.smembers("events:raw")
                sample_events = list(sample_events)[:sample_size]
            
            # Count event types in sample
            for event in sample_events:
                try:
                    event_data = json.loads(event)
                    event_str = str(event_data).lower()
                    
                    if "memory" in event_str or "mmap" in event_str or "munmap" in event_str:
                        memory_count += 1
                    elif "process" in event_str or "exec" in event_str or "fork" in event_str or "exit" in event_str:
                        process_count += 1
                    elif "kernel" in event_str or "module" in event_str or "init_module" in event_str:
                        kernel_count += 1
                    elif "performance" in event_str or "cpu" in event_str or "getpid" in event_str or "brk" in event_str:
                        perf_count += 1
                    else:
                        # If we can't categorize, distribute evenly
                        memory_count += 1
                except:
                    continue
            
            # Scale up the counts based on sample
            if sample_size > 0:
                scale_factor = events_count / sample_size
                memory_count = int(memory_count * scale_factor)
                process_count = int(process_count * scale_factor)
                kernel_count = int(kernel_count * scale_factor)
                perf_count = int(perf_count * scale_factor)
        
        ai_count = threat_count
        
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
                
            # Check for new events in events:raw
            events_type = await redis_conn.type("events:raw")
            events = []
            
            if events_type == "list":
                events = await redis_conn.lrange("events:raw", 0, 0)
            elif events_type == "string":
                event_data = await redis_conn.get("events:raw")
                if event_data:
                    events = [event_data]
            elif events_type == "set":
                events = await redis_conn.smembers("events:raw")
                events = list(events)[:1]
            
            if events:
                try:
                    event_data = json.loads(events[0])
                    # Determine event type
                    event_type = "unknown"
                    if "memory" in str(event_data).lower():
                        event_type = "memory"
                    elif "process" in str(event_data).lower() or "exec" in str(event_data).lower():
                        event_type = "process"
                    elif "kernel" in str(event_data).lower() or "module" in str(event_data).lower():
                        event_type = "kernel"
                    elif "performance" in str(event_data).lower() or "cpu" in str(event_data).lower():
                        event_type = "performance"
                    
                    await manager.broadcast({
                        "type": "new_event",
                        "stream": event_type,
                        "data": event_data,
                        "timestamp": time.time()
                    })
                except Exception as e:
                    logger.debug(f"Error processing event: {e}")
            
            # Check for new AI analyses in threat:current
            threat_type = await redis_conn.type("threat:current")
            analyses = []
            
            if threat_type == "list":
                analyses = await redis_conn.lrange("threat:current", 0, 0)
            elif threat_type == "string":
                analysis_data = await redis_conn.get("threat:current")
                if analysis_data:
                    analyses = [analysis_data]
            elif threat_type == "set":
                analyses = await redis_conn.smembers("threat:current")
                analyses = list(analyses)[:1]
            
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
