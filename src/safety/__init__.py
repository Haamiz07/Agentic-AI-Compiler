"""Safety and validation components for the AGentic_C compiler."""
from .analysis import SecurityAnalyzer
from .controller import SafeOptimizationController
from .models import (OptimizationAttemptRecord, PolicyDecision,
                     SecurityFinding, ValidationResult)
from .policy import PassPolicy
from .validator import CandidateValidator

__all__ = ["SecurityAnalyzer", "SafeOptimizationController", "PassPolicy",
           "PolicyDecision", "SecurityFinding", "ValidationResult",
           "OptimizationAttemptRecord", "CandidateValidator"]
