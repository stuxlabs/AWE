"""
Reconnaissance Agent for XSS vulnerability discovery
"""
import logging
import os
from typing import List
from agno.agent import Agent
from playwright.async_api import async_playwright

from ..models import NucleiResult
from ..utils.nuclei_runner import run_nuclei_direct, parse_nuclei_results

# Import persistence components
try:
    from persistence import PersistenceCandidate, PersistenceCandidateExtractor
    HAS_PERSISTENCE = True
except ImportError:
    HAS_PERSISTENCE = False
    logging.warning("Persistence module not available - OAST functionality will be limited")


class ReconAgent(Agent):
    """Agent responsible for running Nuclei and parsing results"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize persistence extractor if available
        if HAS_PERSISTENCE:
            self.persistence_extractor = PersistenceCandidateExtractor()
        else:
            self.persistence_extractor = None

    async def run(self, target_url: str) -> List[NucleiResult]:
        """Run Nuclei against target and return parsed results"""
        self.logger.info(f"Starting reconnaissance on {target_url}")

        os.makedirs("./results", exist_ok=True)
        output_file = os.path.abspath("./results/nuclei_output.json")

        try:
            success = run_nuclei_direct(target_url, output_file)

            if not success:
                self.logger.error("Failed to run Nuclei")
                return []

            results = parse_nuclei_results(output_file)
            self.logger.info(f"Found {len(results)} potential XSS vulnerabilities")

            return results

        finally:
            if os.path.exists(output_file):
                self.logger.debug(f"Nuclei output saved to: {output_file}")

    async def get_persistence_candidates(self, target_url: str) -> List:
        """
        Discover persistence candidates for OAST triggering

        Args:
            target_url: Target URL to analyze for persistence points

        Returns:
            List of PersistenceCandidate objects with scored persistence potential
        """
        self.logger.info(f"Discovering persistence candidates for {target_url}")

        if not HAS_PERSISTENCE or not self.persistence_extractor:
            self.logger.warning("Persistence analysis not available - returning empty candidates list")
            return []

        try:
            # Use Playwright to fetch page content and analyze for persistence points
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                try:
                    # Navigate to target URL
                    response = await page.goto(target_url, wait_until='networkidle', timeout=30000)

                    if not response:
                        self.logger.warning(f"No response received from {target_url}")
                        return []

                    # Get page content
                    html_content = await page.content()
                    response_status = response.status

                    # Extract persistence candidates from HTML
                    candidates = self.persistence_extractor.extract_from_html(
                        url=target_url,
                        html_content=html_content,
                        response_status=response_status
                    )

                    self.logger.info(f"Found {len(candidates)} persistence candidates")

                    # Log candidate details
                    for candidate in candidates:
                        score = self.persistence_extractor.scorer.compute_persistence_score(candidate)
                        self.logger.debug(f"Candidate {candidate.id}: score={score:.2f}, method={candidate.method}, url={candidate.url}")

                    return candidates

                except Exception as e:
                    self.logger.error(f"Error analyzing {target_url} for persistence: {e}")
                    return []
                finally:
                    await browser.close()

        except Exception as e:
            self.logger.error(f"Failed to discover persistence candidates: {e}")
            return []