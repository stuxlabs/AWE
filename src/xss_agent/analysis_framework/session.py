"""
Deep Analysis Session

Orchestrates multi-stage serial analysis for a single test attempt.
"""

from typing import List, Optional
import logging
from datetime import datetime

from .base import AnalysisResult, TestAttempt, StageFailedException
from .config import AnalysisConfig
from .stages import (
    TransformationAnalysisStage,
    ContextDetectionStage,
    ProtectionFingerprintingStage,
    BypassStrategyStage
)


class DeepAnalysisSession:
    """
    Manages a deep analysis session for one payload attempt.

    Runs stages serially, each building on insights from previous stages.
    Stops when LLM indicates no more insights or max stages reached.
    """

    def __init__(
        self,
        attempt: TestAttempt,
        llm_client,
        config: Optional[AnalysisConfig] = None
    ):
        """
        Initialize analysis session.

        Args:
            attempt: The test attempt to analyze
            llm_client: LLM client for analysis
            config: Configuration object
        """
        self.attempt = attempt
        self.llm = llm_client
        self.config = config or AnalysisConfig.default()
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize stages
        self.stages = self._initialize_stages()
        self.results: List[AnalysisResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def _initialize_stages(self) -> List:
        """Initialize analysis stages in order"""
        stage_classes = [
            TransformationAnalysisStage,
            ContextDetectionStage,
            ProtectionFingerprintingStage,
            BypassStrategyStage,
        ]

        stages = []
        for stage_class in stage_classes:
            stage_config = self._get_stage_config(stage_class.__name__)
            stages.append(stage_class(self.llm, stage_config))

        return stages

    def _get_stage_config(self, stage_name: str) -> dict:
        """Get configuration for specific stage"""
        config_map = {
            'TransformationAnalysisStage': self.config.transformation_stage_config,
            'ContextDetectionStage': self.config.context_stage_config,
            'ProtectionFingerprintingStage': self.config.protection_stage_config,
            'BypassStrategyStage': self.config.bypass_stage_config,
        }
        return config_map.get(stage_name, {})

    async def run_until_exhausted(self) -> List[AnalysisResult]:
        """
        Run analysis stages serially until exhausted.

        Returns:
            List of AnalysisResult from each stage
        """
        self.start_time = datetime.now()
        self.logger.info(f"Starting deep analysis session for attempt #{self.attempt.attempt_number}")

        try:
            stages_to_run = min(len(self.stages), self.config.max_analysis_stages)

            for i, stage in enumerate(self.stages[:stages_to_run]):
                self.logger.info(f"Running stage {i+1}/{stages_to_run}: {stage.get_stage_name()}")

                try:
                    result = await stage.analyze(self.attempt, self.results)
                    self.results.append(result)

                    if self.config.verbose_analysis:
                        self.logger.debug(f"Stage result: {result.get_summary()}")

                    # Check if we should continue
                    if self.config.enable_adaptive_stages:
                        if not result.continue_analysis:
                            self.logger.info(f"Stopping analysis: {result.reasoning}")
                            break
                        if result.error:
                            self.logger.warning(f"Stage had error but continuing: {result.error}")

                except Exception as e:
                    self.logger.error(f"Stage {stage.get_stage_name()} failed: {e}")
                    # Add error result and continue if possible
                    error_result = AnalysisResult(
                        stage_name=stage.get_stage_name(),
                        insights=[f"Stage failed: {str(e)[:100]}"],
                        data={'error': str(e)},
                        continue_analysis=True,  # Try to continue
                        reasoning=f"Error occurred but attempting to continue",
                        error=str(e)
                    )
                    self.results.append(error_result)

            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            self.logger.info(f"Analysis session complete: {len(self.results)} stages in {duration:.2f}s")

            return self.results

        except Exception as e:
            self.logger.error(f"Fatal error in analysis session: {e}")
            self.end_time = datetime.now()
            raise StageFailedException(f"Analysis session failed: {e}")

    def get_summary(self) -> str:
        """Get brief summary of session"""
        if not self.results:
            return "No analysis performed"

        insights = []
        for result in self.results:
            insights.extend(result.insights)

        return f"Completed {len(self.results)} stages | {len(insights)} insights"

    def get_all_insights(self) -> List[str]:
        """Get all insights from all stages"""
        all_insights = []
        for result in self.results:
            all_insights.extend(result.insights)
        return all_insights

    def get_final_strategy(self) -> Optional[dict]:
        """Get bypass strategy from final stage (if exists)"""
        if self.results and len(self.results) >= 4:
            # Last stage should be bypass strategy
            return self.results[-1].data
        return None

    def get_confidence(self) -> int:
        """Get overall confidence from session"""
        if not self.results:
            return 0

        # Average confidence from all stages
        confidences = [r.confidence for r in self.results if r.confidence > 0]
        if not confidences:
            return 50  # Default

        return sum(confidences) // len(confidences)

    def has_bypass_strategy(self) -> bool:
        """Check if session produced a bypass strategy"""
        strategy = self.get_final_strategy()
        return strategy is not None and 'bypass_technique' in strategy

    def to_dict(self) -> dict:
        """Convert session to dictionary"""
        return {
            'attempt_number': self.attempt.attempt_number,
            'payload': self.attempt.payload,
            'stages_run': len(self.results),
            'results': [r.to_dict() for r in self.results],
            'summary': self.get_summary(),
            'all_insights': self.get_all_insights(),
            'final_strategy': self.get_final_strategy(),
            'confidence': self.get_confidence(),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
        }
