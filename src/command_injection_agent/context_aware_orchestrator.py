"""
Context-Aware Command Injection Orchestrator with Escalation Strategy

STRATEGY:
1. Phase 1: Try rule-based probes (timing, markers, output detection) - FAST, FREE
2. Phase 2: If all fail, analyze context (shell type, quotes, filters) - SMART
3. Phase 3: Generate LLM payloads with failure context - ADAPTIVE
"""
from dataclasses import dataclass
from typing import List, Optional, Callable, Awaitable
import time
import re

from .cmd_detector import CMDInjectionDetector, CMDInjectionResult, InjectionTechnique
from .analyzers.context_analyzer import CMDContextAnalyzer, CommandReflection
from .analyzers.llm_cmd_engine import CMDLLMEngine, CMDPayload


@dataclass
class CMDTestResult:
    """Result of command injection testing"""
    vulnerable: bool
    successful_payload: Optional[str]
    technique: str  # 'rule_based' or 'llm_adaptive'
    flag: Optional[str]
    phases_executed: List[str]
    failures: List[str]
    reasoning: Optional[str]
    detection_method: Optional[str]  # 'output', 'timing', 'error'


class ContextAwareCMDOrchestrator:
    """
    Orchestrates Command Injection testing with intelligent escalation

    Phase 1: Rule-based probes (cheap, fast)
    Phase 2: Context analysis (if Phase 1 fails)
    Phase 3: LLM adaptive payloads (with failure info)
    """

    def __init__(self, llm_client, cost_tracker=None):
        self.detector = CMDInjectionDetector()
        self.context_analyzer = CMDContextAnalyzer()
        self.llm_engine = CMDLLMEngine(llm_client, cost_tracker)
        self.cost_tracker = cost_tracker

    async def test_parameter(
        self,
        parameter: str,
        original_value: str,
        submit_func: Callable[[str], Awaitable[tuple[str, float]]],  # Returns (response, time)
        baseline_response: str,
        baseline_time: float
    ) -> CMDTestResult:
        """
        Test a parameter for command injection with intelligent escalation

        Args:
            parameter: Parameter name
            original_value: Original parameter value
            submit_func: Async function that returns (response, response_time)
            baseline_response: Normal response for comparison
            baseline_time: Normal response time

        Returns:
            CMDTestResult
        """

        phases_executed = []
        failures = []

        print(f"\n{'='*70}")
        print(f"COMMAND INJECTION TESTING: {parameter}")
        print(f"{'='*70}\n")

        # ========================================================================
        # PHASE 1: Rule-Based Detection (Fast & Free)
        # ========================================================================
        print("📍 PHASE 1: Rule-Based Detection")
        print("-" * 70)

        phases_executed.append("phase1_rule_based")

        # Get detection probes
        probes = self.detector.get_probes(original_value)

        print(f"  Testing {len(probes)} rule-based probes...")

        vulnerable = False
        successful_probe = None

        for probe in probes:
            print(f"  Testing: {probe.description} - {probe.payload[:60]}...")

            try:
                response, response_time = await submit_func(probe.payload)
                result = self.detector.analyze_response(probe, response, response_time)

                if result.vulnerable:
                    print(f"  ✅ Vulnerable! Method: {probe.detection_method}")
                    print(f"     Evidence: {result.evidence}")
                    vulnerable = True
                    successful_probe = probe
                    break
                else:
                    failures.append(f"Probe failed: {probe.description}")

            except Exception as e:
                failures.append(f"Probe error: {probe.description} - {str(e)}")

        if not vulnerable:
            print(f"  ❌ No command injection detected with probes")
            print(f"  Total failures: {len(failures)}")
            return CMDTestResult(
                vulnerable=False,
                successful_payload=None,
                technique="none",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="Rule-based probes failed to detect command injection",
                detection_method=None
            )

        print(f"\n  ✅ Command injection confirmed!")
        print(f"     Detection Method: {successful_probe.detection_method}")
        print(f"     Technique: {successful_probe.technique.value}")

        # Try flag extraction with database payloads
        print(f"\n  Trying database flag extraction payloads...")
        flag_payloads = self.detector.get_flag_extraction_payloads(original_value)

        for payload in flag_payloads[:20]:  # Try first 20
            try:
                response, _ = await submit_func(payload)
                flag = self.detector.check_flag_in_response(response)

                if flag:
                    print(f"  🎉 SUCCESS with rule-based payload!")
                    return CMDTestResult(
                        vulnerable=True,
                        successful_payload=payload,
                        technique="rule_based",
                        flag=flag,
                        phases_executed=phases_executed,
                        failures=failures,
                        reasoning="Database flag extraction payload worked",
                        detection_method=successful_probe.detection_method
                    )
                else:
                    failures.append(f"Flag payload failed: {payload[:50]}...")

            except Exception as e:
                failures.append(f"Flag payload error: {payload[:50]}... - {str(e)}")

        print(f"  ❌ All database flag payloads failed ({len(flag_payloads)} tried)")

        # ========================================================================
        # PHASE 2: Context & Filter Analysis (Smart Detection)
        # ========================================================================
        print(f"\n📍 PHASE 2: Context Analysis")
        print("-" * 70)

        phases_executed.append("phase2_context_analysis")

        # Inject canary to analyze context
        canary = "CMD_CANARY_ABC789"
        print(f"  Injecting canary: {canary}")

        try:
            canary_response, _ = await submit_func(canary)
        except Exception as e:
            print(f"  ❌ Canary injection failed: {e}")
            return CMDTestResult(
                vulnerable=True,
                successful_payload=successful_probe.payload,
                technique="detected_but_cannot_exploit",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="Command injection detected but cannot inject canary",
                detection_method=successful_probe.detection_method
            )

        # Analyze context
        reflections = self.context_analyzer.find_reflections(canary_response, canary)

        if not reflections:
            print("  ⚠️  Canary not reflected (blind injection)")
            # For blind injection, we need different approach
            reflection = None
        else:
            print(f"  ✅ Found {len(reflections)} reflection point(s)")
            reflection = reflections[0]

            print(f"\n  Reflection Context:")
            print(f"    Context: {reflection.context.value}")
            print(f"    OS: {reflection.os_type}")
            print(f"    In Quotes: {reflection.in_quotes} ({reflection.quote_type})")
            print(f"    Command Prefix: {reflection.command_prefix}")
            print(f"    Breakout: {reflection.breakout_needed}")

        # Detect blocked characters/commands
        print(f"\n  Detecting filters...")
        blocked_chars, blocked_commands = await self._detect_filters(
            submit_func, baseline_response, baseline_time
        )

        if blocked_chars:
            print(f"    Blocked chars: {', '.join(blocked_chars)}")
        if blocked_commands:
            print(f"    Blocked commands: {', '.join(blocked_commands)}")

        # ========================================================================
        # PHASE 3: LLM Adaptive Payload Generation (With Failure Context)
        # ========================================================================
        print(f"\n📍 PHASE 3: LLM Adaptive Payload Generation")
        print("-" * 70)

        phases_executed.append("phase3_llm_adaptive")

        # Create a default reflection if blind injection
        if not reflection:
            from .analyzers.context_analyzer import CommandReflection, CommandContext
            reflection = CommandReflection(
                context=CommandContext.SHELL_ARGUMENT,
                position=0,
                context_before="",
                context_after="",
                in_quotes=False,
                quote_type=None,
                command_prefix="unknown",
                os_type="linux",  # Assume Linux
                breakout_needed=";"
            )
            print("  Using default context for blind injection")

        print(f"  Generating context-aware payloads with LLM...")
        print(f"  Context: {reflection.context.value}")
        print(f"  OS: {reflection.os_type}")
        print(f"  Filters detected: {len(blocked_chars) + len(blocked_commands)}")
        print(f"  Failed attempts: {len(failures)}")

        # Generate adaptive payloads
        llm_payloads = await self.llm_engine.generate_context_aware_payloads(
            reflection=reflection,
            blocked_chars=blocked_chars,
            blocked_commands=blocked_commands,
            goal="flag_extraction",
            num_payloads=10
        )

        if not llm_payloads:
            print("  ❌ LLM failed to generate payloads")
            return CMDTestResult(
                vulnerable=True,
                successful_payload=successful_probe.payload,
                technique="detected_cannot_exploit",
                flag=None,
                phases_executed=phases_executed,
                failures=failures,
                reasoning="LLM payload generation failed",
                detection_method=successful_probe.detection_method
            )

        print(f"  ✅ Generated {len(llm_payloads)} adaptive payloads\n")

        # Test LLM-generated payloads
        for i, llm_payload in enumerate(llm_payloads, 1):
            print(f"  Payload {i}/{len(llm_payloads)}:")
            print(f"    Technique: {llm_payload.technique}")
            print(f"    Confidence: {llm_payload.confidence}")
            print(f"    OS Target: {llm_payload.os_target}")
            print(f"    Payload: {llm_payload.payload[:100]}...")
            print(f"    Reasoning: {llm_payload.reasoning[:150]}...")

            try:
                response, _ = await submit_func(llm_payload.payload)
                flag = self.detector.check_flag_in_response(response)

                if flag:
                    print(f"  🎉 SUCCESS with LLM payload!")
                    return CMDTestResult(
                        vulnerable=True,
                        successful_payload=llm_payload.payload,
                        technique="llm_adaptive",
                        flag=flag,
                        phases_executed=phases_executed,
                        failures=failures,
                        reasoning=llm_payload.reasoning,
                        detection_method="output"
                    )
                else:
                    failures.append(f"LLM payload failed: {llm_payload.technique}")
                    print(f"    ❌ No flag found")

            except Exception as e:
                failures.append(f"LLM payload error: {llm_payload.technique} - {str(e)}")
                print(f"    ❌ Error: {e}")

        # All LLM payloads failed
        print(f"\n  ❌ All LLM payloads failed")

        return CMDTestResult(
            vulnerable=True,
            successful_payload=successful_probe.payload,
            technique="detected_cannot_exploit",
            flag=None,
            phases_executed=phases_executed,
            failures=failures,
            reasoning=f"All techniques exhausted. Tried {len(failures)} payloads.",
            detection_method=successful_probe.detection_method
        )

    async def _detect_filters(
        self,
        submit_func: Callable[[str], Awaitable[tuple[str, float]]],
        baseline: str,
        baseline_time: float
    ) -> tuple[List[str], List[str]]:
        """Detect blocked characters and commands"""

        blocked_chars = []
        blocked_commands = []

        # Test common separator characters
        test_chars = [';', '|', '&', '$', '`', '\n', '<', '>', '(', ')']

        for char in test_chars:
            test_payload = f"test{char}test"
            try:
                response, _ = await submit_func(test_payload)
                if self._is_filtered(response, baseline):
                    blocked_chars.append(char)
            except:
                blocked_chars.append(char)

        # Test common commands
        test_commands = ['cat', 'ls', 'id', 'whoami', 'find', 'grep']

        for cmd in test_commands:
            test_payload = f"{cmd}"
            try:
                response, _ = await submit_func(test_payload)
                if self._is_filtered(response, baseline):
                    blocked_commands.append(cmd)
            except:
                blocked_commands.append(cmd)

        return blocked_chars, blocked_commands

    def _is_filtered(self, response: str, baseline: str) -> bool:
        """Check if response indicates filtering"""

        filter_indicators = [
            "blocked", "denied", "forbidden", "not allowed",
            "invalid", "malicious", "filtered", "403", "406"
        ]

        response_lower = response.lower()
        for indicator in filter_indicators:
            if indicator in response_lower and indicator not in baseline.lower():
                return True

        # Significantly different response length
        if len(response) < len(baseline) * 0.5:
            return True

        return False

    def generate_report(self, result: CMDTestResult) -> str:
        """Generate a detailed report"""

        report = []
        report.append("\n" + "="*70)
        report.append("COMMAND INJECTION TESTING REPORT")
        report.append("="*70)

        report.append(f"\n🎯 Result: {'VULNERABLE' if result.vulnerable else 'NOT VULNERABLE'}")
        report.append(f"📊 Technique: {result.technique}")

        if result.detection_method:
            report.append(f"🔍 Detection Method: {result.detection_method}")

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
