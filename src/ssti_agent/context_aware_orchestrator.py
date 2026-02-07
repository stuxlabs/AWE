"""
Context-Aware SSTI Orchestrator with Escalation Strategy

STRATEGY:
1. Phase 1: Try rule-based probes and database payloads (FAST, FREE)
2. Phase 2: If all fail, analyze context and filters (SMART)
3. Phase 3: Generate LLM payloads with failure context (ADAPTIVE)
"""
from dataclasses import dataclass
from typing import List, Optional, Callable, Awaitable
import asyncio

from .ssti_detector import SSTIDetector, SSTIVulnerability, TemplateEngine
from .analyzers.context_analyzer import SSTIContextAnalyzer, TemplateReflection
from .analyzers.filter_detector import SSTIFilterDetector, SSTIFilterProfile
from .analyzers.llm_ssti_engine import SSTILLMEngine, SSTIPayload


@dataclass
class SSTITestResult:
    """Result of SSTI testing"""
    vulnerable: bool
    engine: Optional[TemplateEngine]
    successful_payload: Optional[str]
    technique: str  # 'rule_based' or 'llm_adaptive'
    flag: Optional[str]
    phases_executed: List[str]
    failures: List[str]
    reasoning: Optional[str]


class ContextAwareSSTIOrchestrator:
    """
    Orchestrates SSTI testing with intelligent escalation

    Phase 1: Rule-based probes (cheap, fast)
    Phase 2: Context analysis (if Phase 1 fails)
    Phase 3: LLM adaptive payloads (with failure info)
    """

    def __init__(self, llm_client, cost_tracker=None):
        self.detector = SSTIDetector()
        self.context_analyzer = SSTIContextAnalyzer()
        self.filter_detector = SSTIFilterDetector()
        self.llm_engine = SSTILLMEngine(llm_client, cost_tracker)
        self.cost_tracker = cost_tracker

    async def test_parameter(
        self,
        parameter: str,
        submit_func: Callable[[str], Awaitable[str]],
        baseline_response: str
    ) -> SSTITestResult:
        """
        Test a parameter for SSTI with intelligent escalation

        Args:
            parameter: Parameter name
            submit_func: Async function to submit payloads
            baseline_response: Normal response for comparison

        Returns:
            SSTITestResult
        """

        phases_executed = []
        failures = []

        print(f"\n{'='*70}")
        print(f"SSTI TESTING: {parameter}")
        print(f"{'='*70}\n")

        # ========================================================================
        # PHASE 1: Rule-Based Detection (Fast & Free)
        # ========================================================================
        print("📍 PHASE 1: Rule-Based Detection")
        print("-" * 70)

        phases_executed.append("phase1_rule_based")

        # Try mathematical probes to detect template engine
        detected_engine = None
        probe_payload = None

        for probe in self.detector.PROBES:
            print(f"  Testing probe: {probe.payload}")
            try:
                response = await submit_func(probe.payload)
                result = self.detector.detect_ssti(response, probe.payload, probe.expected_result)

                if result:
                    detected_engine = probe.engine
                    probe_payload = probe.payload
                    print(f"  ✅ Template engine detected: {detected_engine.value}")
                    break
                else:
                    failures.append(f"Probe failed: {probe.payload}")

            except Exception as e:
                failures.append(f"Probe error: {probe.payload} - {str(e)}")

        if not detected_engine:
            print("  ❌ No template engine detected with rule-based probes")
            print(f"  Total failures: {len(failures)}")
            return SSTITestResult(
                vulnerable=False,
                engine=None,
                successful_payload=None,
                technique="none",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="Rule-based probes failed to detect SSTI"
            )

        # Try database RCE payloads for detected engine
        print(f"\n  Trying database RCE payloads for {detected_engine.value}...")
        database_payloads = self.detector.get_rce_payloads(detected_engine)

        for payload in database_payloads[:5]:  # Try first 5 database payloads
            print(f"  Testing: {payload[:80]}...")
            try:
                response = await submit_func(payload)
                flag = self.detector.check_flag_in_response(response)

                if flag:
                    print(f"  🎉 SUCCESS with rule-based payload!")
                    return SSTITestResult(
                        vulnerable=True,
                        engine=detected_engine,
                        successful_payload=payload,
                        technique="rule_based",
                        flag=flag,
                        phases_executed=phases_executed,
                        failures=failures,
                        reasoning="Database payload worked"
                    )
                else:
                    failures.append(f"Database payload failed: {payload[:50]}...")

            except Exception as e:
                failures.append(f"Database payload error: {payload[:50]}... - {str(e)}")

        print(f"  ❌ All database payloads failed ({len(database_payloads)} tried)")

        # ========================================================================
        # PHASE 2: Context & Filter Analysis (Smart Detection)
        # ========================================================================
        print(f"\n📍 PHASE 2: Context & Filter Analysis")
        print("-" * 70)

        phases_executed.append("phase2_context_analysis")

        # Inject canary to find reflection context
        canary = "SSTI_CANARY_XYZ123"
        print(f"  Injecting canary: {canary}")

        try:
            canary_response = await submit_func(canary)
        except Exception as e:
            print(f"  ❌ Canary injection failed: {e}")
            return SSTITestResult(
                vulnerable=True,  # We know it's vulnerable from Phase 1
                engine=detected_engine,
                successful_payload=None,
                technique="detected_but_cannot_exploit",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="Template engine detected but cannot inject canary for context analysis"
            )

        # Analyze where canary landed
        reflections = self.context_analyzer.find_reflections(canary_response, canary)

        if not reflections:
            print("  ⚠️  Canary not reflected in response")
            return SSTITestResult(
                vulnerable=True,
                engine=detected_engine,
                successful_payload=probe_payload,
                technique="detected_no_reflection",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="Template engine detected but input not reflected"
            )

        print(f"  ✅ Found {len(reflections)} reflection point(s)")
        reflection = reflections[0]  # Use first reflection

        print(f"\n  Reflection Context:")
        print(f"    Type: {reflection.context.value}")
        print(f"    In Quotes: {reflection.in_quotes}")
        print(f"    Surrounding: {reflection.surrounding_syntax}")
        print(f"    Breakout: {reflection.breakout_needed}")

        # Detect filters
        print(f"\n  Detecting filters...")
        filter_profile = await self.filter_detector.detect_filters(
            submit_func, baseline_response, parameter
        )

        # ========================================================================
        # PHASE 3: LLM Adaptive Payload Generation (With Failure Context)
        # ========================================================================
        print(f"\n📍 PHASE 3: LLM Adaptive Payload Generation")
        print("-" * 70)

        phases_executed.append("phase3_llm_adaptive")

        print(f"  Generating context-aware payloads with LLM...")
        print(f"  Context: {reflection.context.value}")
        print(f"  Engine: {detected_engine.value}")
        print(f"  Filters: {filter_profile.strictness_level}")
        print(f"  Failed attempts: {len(failures)}")

        # Generate adaptive payloads with full context
        llm_payloads = await self.llm_engine.generate_context_aware_payloads(
            engine=detected_engine,
            reflection=reflection,
            filter_profile=filter_profile,
            goal="rce",
            num_payloads=10
        )

        if not llm_payloads:
            print("  ❌ LLM failed to generate payloads")
            return SSTITestResult(
                vulnerable=True,
                engine=detected_engine,
                successful_payload=probe_payload,
                technique="detected_cannot_exploit",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="LLM payload generation failed"
            )

        print(f"  ✅ Generated {len(llm_payloads)} adaptive payloads\n")

        # Test LLM-generated payloads
        for i, llm_payload in enumerate(llm_payloads, 1):
            print(f"  Payload {i}/{len(llm_payloads)}:")
            print(f"    Technique: {llm_payload.technique}")
            print(f"    Confidence: {llm_payload.confidence}")
            print(f"    Payload: {llm_payload.payload[:100]}...")
            print(f"    Reasoning: {llm_payload.reasoning[:150]}...")

            try:
                response = await submit_func(llm_payload.payload)
                flag = self.detector.check_flag_in_response(response)

                if flag:
                    print(f"  🎉 SUCCESS with LLM payload!")
                    return SSTITestResult(
                        vulnerable=True,
                        engine=detected_engine,
                        successful_payload=llm_payload.payload,
                        technique="llm_adaptive",
                        flag=flag,
                        phases_executed=phases_executed,
                        failures=failures,
                        reasoning=llm_payload.reasoning
                    )
                else:
                    failures.append(f"LLM payload failed: {llm_payload.technique}")
                    print(f"    ❌ No flag found")

            except Exception as e:
                failures.append(f"LLM payload error: {llm_payload.technique} - {str(e)}")
                print(f"    ❌ Error: {e}")

        # All LLM payloads failed
        print(f"\n  ❌ All LLM payloads failed")

        return SSTITestResult(
            vulnerable=True,
            engine=detected_engine,
            successful_payload=probe_payload,
            technique="detected_cannot_exploit",
            flag=None,
            phases_executed=phases_executed,
            failures=failures,
            reasoning=f"All techniques exhausted. Tried {len(failures)} payloads."
        )

    def generate_report(self, result: SSTITestResult) -> str:
        """Generate a detailed report of the testing"""

        report = []
        report.append("\n" + "="*70)
        report.append("SSTI TESTING REPORT")
        report.append("="*70)

        report.append(f"\n🎯 Result: {'VULNERABLE' if result.vulnerable else 'NOT VULNERABLE'}")

        if result.engine:
            report.append(f"🔧 Engine: {result.engine.value}")

        report.append(f"📊 Technique: {result.technique}")
        report.append(f"🔄 Phases Executed: {', '.join(result.phases_executed)}")
        report.append(f"❌ Failed Attempts: {len(result.failures)}")

        if result.flag:
            report.append(f"\n🚩 FLAG CAPTURED: {result.flag}")

        if result.successful_payload:
            report.append(f"\n✅ Successful Payload:")
            report.append(f"   {result.successful_payload}")

        if result.reasoning:
            report.append(f"\n💡 Reasoning:")
            report.append(f"   {result.reasoning}")

        report.append("\n" + "="*70)

        return "\n".join(report)
