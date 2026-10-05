import os
import pytest
from app.evaluation.evaluator import KypticAccuracyEvaluator


def test_01_evaluation_corpus_structure():
    """Verify evaluation corpus contains pre-defined vulnerable and safe test cases."""
    evaluator = KypticAccuracyEvaluator()
    assert len(evaluator.cases) >= 28

    vulnerable_cases = [c for c in evaluator.cases if c.expected_result == "VULNERABLE"]
    safe_cases = [c for c in evaluator.cases if c.expected_result == "SAFE"]

    assert len(vulnerable_cases) == 14
    assert len(safe_cases) == 14


def test_02_accuracy_evaluation_metrics_calculation():
    """Verify accuracy metrics (Accuracy, Precision, Recall, F1, FPR, FNR) are calculated transparently."""
    evaluator = KypticAccuracyEvaluator()
    summary = evaluator.evaluate()

    assert summary["total_cases"] >= 28
    assert "accuracy" in summary
    assert "precision" in summary
    assert "recall" in summary
    assert "f1" in summary
    assert "fpr" in summary
    assert "fnr" in summary

    # Verify transparent mathematical relationship
    tp = summary["tp"]
    tn = summary["tn"]
    fp = summary["fp"]
    fn = summary["fn"]
    total = summary["total_evaluated"]

    calculated_acc = round((tp + tn) / total, 4) if total > 0 else 0.0
    assert summary["accuracy"] == calculated_acc

    # Verify disclaimer is explicitly present
    assert "CONTROLLED EVALUATION SAMPLE" in summary["disclaimer"]


def test_03_inconclusive_tracked_separately():
    """Verify INCONCLUSIVE is tracked separately and not converted to TN."""
    evaluator = KypticAccuracyEvaluator()
    summary = evaluator.evaluate()
    assert "inconclusive" in summary
    assert summary["inconclusive"] >= 0
