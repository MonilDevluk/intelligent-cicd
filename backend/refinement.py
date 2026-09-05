from dataclasses import dataclass, asdict
from typing import Callable, Optional


@dataclass
class RefinementAttempt:
    attempt: int
    patch: str
    status: str
    security_ok: bool
    functional_ok: bool
    ground_truth_ok: bool
    feedback: str


@dataclass
class RefinementResult:
    success: bool
    attempts: list[RefinementAttempt]
    final_patch: Optional[str]
    final_validation: Optional[dict]


def build_validation_feedback(validation) -> str:
    """
    Convert validation results into structured feedback
    that can be supplied to the next patch-generation attempt.
    """

    feedback = []

    if not validation.syntax_ok:
        feedback.append(
            "SYNTAX FAILURE: The generated patch is not valid Python."
        )

    if validation.ground_truth_available:
        if not validation.ground_truth_ok:
            feedback.append(
                "SECURITY FAILURE: The independent security "
                "oracle still detects exploitable behavior."
            )

    if not validation.semgrep_ok:
        feedback.append(
            "STATIC ANALYSIS: Semgrep still reports security findings."
        )

    if not validation.bandit_ok:
        feedback.append(
            "STATIC ANALYSIS: Bandit still reports security findings."
        )

    if not validation.functional_ok:
        feedback.append(
            "FUNCTIONAL FAILURE: Tests did not pass."
        )

    if validation.changed_lines > 0:
        feedback.append(
            f"PATCH SIZE: {validation.changed_lines} changed lines "
            f"across {validation.changed_files} file(s)."
        )

    if not feedback:
        feedback.append(
            "Validation passed. No corrective feedback is required."
        )

    return "\n".join(
        f"- {item}"
        for item in feedback
    )


def refine_patch(
    generate_fn: Callable[[str], str],
    validate_fn: Callable[[str], object],
    initial_prompt: str,
    max_attempts: int = 3,
) -> RefinementResult:
    """
    Generic validation-guided iterative repair loop.

    generate_fn(prompt) -> patch
    validate_fn(patch) -> ValidationResult

    The loop stops immediately when security and functionality
    are both validated.
    """

    attempts = []
    prompt = initial_prompt

    for attempt_number in range(1, max_attempts + 1):

        patch = generate_fn(prompt)

        validation = validate_fn(patch)

        feedback = build_validation_feedback(validation)

        attempt = RefinementAttempt(
            attempt=attempt_number,
            patch=patch,
            status=validation.status,
            security_ok=validation.security_ok,
            functional_ok=validation.functional_ok,
            ground_truth_ok=validation.ground_truth_ok,
            feedback=feedback,
        )

        attempts.append(attempt)

        if (
            validation.security_ok
            and validation.functional_ok
        ):
            return RefinementResult(
                success=True,
                attempts=attempts,
                final_patch=patch,
                final_validation=asdict(validation),
            )

        prompt = (
            initial_prompt
            + "\n\n"
            + "PREVIOUS PATCH VALIDATION FEEDBACK:\n"
            + feedback
            + "\n\n"
            + "Generate a corrected patch that addresses "
              "all reported failures. Return only the complete "
              "replacement source file."
        )

    final = attempts[-1]

    return RefinementResult(
        success=False,
        attempts=attempts,
        final_patch=final.patch,
        final_validation=None,
    )
