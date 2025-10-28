"""
Analysis Summarizer

Compresses deep analysis sessions into compact summaries for memory efficiency.
"""

from typing import List, Dict, Any
import logging
import json

from .base import AnalysisResult
from .config import AnalysisConfig


class AnalysisSummarizer:
    """
    Compresses analysis sessions into brief summaries.

    Ensures:
    - Memory efficiency (summaries vs full data)
    - Key insights preserved
    - Context maintained for future generation
    - Token limits respected
    """

    def __init__(self, llm_client, config: AnalysisConfig = None):
        """
        Initialize summarizer.

        Args:
            llm_client: LLM client for summarization
            config: Configuration object
        """
        self.llm = llm_client
        self.config = config or AnalysisConfig.default()
        self.logger = logging.getLogger(self.__class__.__name__)

    async def summarize(
        self,
        session_results: List[AnalysisResult],
        payload: str,
        attempt_number: int
    ) -> str:
        """
        Compress analysis session into compact summary.

        Args:
            session_results: Results from all analysis stages
            payload: The tested payload
            attempt_number: Attempt number

        Returns:
            Compact summary string (max ~250 tokens)
        """
        self.logger.debug(f"Summarizing {len(session_results)} analysis stages")

        # Quick summary if no LLM needed
        if not session_results:
            return f"Attempt {attempt_number}: {payload[:50]} - No analysis performed"

        # Extract key data
        all_insights = []
        stage_summaries = []

        for result in session_results:
            all_insights.extend(result.insights)
            stage_summaries.append({
                'stage': result.stage_name,
                'insights': result.insights[:2],  # Top 2 insights
                'confidence': result.confidence
            })

        # Build prompt for LLM summarization
        prompt = self._build_summary_prompt(
            attempt_number=attempt_number,
            payload=payload,
            stage_summaries=stage_summaries,
            all_insights=all_insights
        )

        try:
            # Use lower temperature for focused summarization
            # simple_chat is synchronous, not async
            summary = self.llm.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=0.3
            )

            # Validate length
            if len(summary) > self.config.summary_max_tokens * 4:  # ~4 chars per token
                self.logger.warning(f"Summary too long ({len(summary)} chars), truncating")
                summary = summary[:self.config.summary_max_tokens * 4]

            return summary.strip()

        except Exception as e:
            self.logger.error(f"LLM summarization failed: {e}, using fallback")
            return self._fallback_summary(
                attempt_number, payload, stage_summaries, all_insights
            )

    def _build_summary_prompt(
        self,
        attempt_number: int,
        payload: str,
        stage_summaries: List[Dict],
        all_insights: List[str]
    ) -> str:
        """Build prompt for summary generation"""
        return f"""
Compress this analysis into a brief summary (MAX 200 tokens).

ATTEMPT: #{attempt_number}
PAYLOAD: {payload}

STAGE RESULTS:
{json.dumps(stage_summaries, indent=2)}

ALL INSIGHTS:
{chr(10).join(f"- {insight}" for insight in all_insights)}

Create a BRIEF summary in this format:
PROTECTION: [what's blocking]
CONTEXT: [where it lands]
LEARNED: [2-3 key insights]
NEXT: [specific bypass to try]

Be CONCISE. Maximum 200 tokens.
"""

    def _fallback_summary(
        self,
        attempt_number: int,
        payload: str,
        stage_summaries: List[Dict],
        all_insights: List[str]
    ) -> str:
        """Fallback summary without LLM"""
        # Extract key info
        protections = [i for i in all_insights if any(k in i.lower() for k in ['waf', 'filter', 'encoding'])]
        context = [i for i in all_insights if any(k in i.lower() for k in ['html', 'javascript', 'context'])]
        bypasses = [i for i in all_insights if any(k in i.lower() for k in ['bypass', 'try', 'technique'])]

        summary = f"Attempt {attempt_number}: {payload[:50]}\n"
        if protections:
            summary += f"PROTECTION: {'; '.join(protections[:2])}\n"
        if context:
            summary += f"CONTEXT: {'; '.join(context[:2])}\n"
        if bypasses:
            summary += f"NEXT: {'; '.join(bypasses[:2])}\n"

        return summary

    async def meta_summarize(
        self,
        summaries: List[str],
        max_tokens: int = 500
    ) -> str:
        """
        Meta-summarize multiple summaries (for history compression).

        Args:
            summaries: List of individual summaries
            max_tokens: Maximum tokens for output

        Returns:
            Compressed meta-summary
        """
        self.logger.info(f"Meta-summarizing {len(summaries)} summaries")

        prompt = f"""
Compress these {len(summaries)} attempt summaries into ONE meta-summary.

SUMMARIES:
{chr(10).join(f"{i+1}. {s}" for i, s in enumerate(summaries))}

Create ONE concise meta-summary (MAX {max_tokens} tokens):
PATTERNS OBSERVED: [recurring protections/failures]
KEY LEARNINGS: [what consistently works/fails]
RECOMMENDED STRATEGY: [what to try next]

Be VERY concise.
"""

        try:
            # simple_chat is synchronous, not async
            meta_summary = self.llm.simple_chat(
                model="claude-4-sonnet",
                message=prompt,
                temperature=0.3
            )
            return meta_summary.strip()

        except Exception as e:
            self.logger.error(f"Meta-summarization failed: {e}")
            # Fallback: just take first and last summary
            return f"COMPRESSED: {summaries[0][:200]}... {summaries[-1][:200]}"

    def extract_key_insights(self, session_results: List[AnalysisResult]) -> Dict[str, List[str]]:
        """
        Extract categorized insights from session.

        Returns:
            Dict with categories: protections, contexts, bypasses, errors
        """
        categorized = {
            'protections': [],
            'contexts': [],
            'bypasses': [],
            'errors': []
        }

        for result in session_results:
            for insight in result.insights:
                lower = insight.lower()
                if any(k in lower for k in ['waf', 'filter', 'encoding', 'protection', 'sanitiz']):
                    categorized['protections'].append(insight)
                elif any(k in lower for k in ['html', 'javascript', 'context', 'tag', 'attribute']):
                    categorized['contexts'].append(insight)
                elif any(k in lower for k in ['bypass', 'technique', 'try', 'avoid', 'use']):
                    categorized['bypasses'].append(insight)
                elif any(k in lower for k in ['error', 'fail']):
                    categorized['errors'].append(insight)

        return categorized
