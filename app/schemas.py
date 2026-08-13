"""Pydantic schemas for request/response models"""
from typing import List, Optional
from pydantic import BaseModel, Field, HttpUrl


class AnalyzeURLRequest(BaseModel):
    """Request schema for URL analysis"""
    url: str = Field(..., description="URL to analyze")


class VerdictResponse(BaseModel):
    """Response schema for URL analysis verdict"""
    url: str
    verdict: str = Field(..., description="safe, suspicious, or malicious")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str]
    cached: bool = False
    analysis_time_ms: int


class HealthResponse(BaseModel):
    """Response schema for health check"""
    status: str
    redis: bool
    model_loaded: bool


class AnalysisResult(BaseModel):
    """Internal analysis result from individual analyzers"""
    score: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)


class ScrapeResult(BaseModel):
    """Result from content scraping"""
    html: Optional[str] = None
    title: Optional[str] = None
    final_url: Optional[str] = None
    requests_made: List[str] = Field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_successful(self) -> bool:
        """Check if scrape was successful"""
        return self.error is None and self.html is not None
