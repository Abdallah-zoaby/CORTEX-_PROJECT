"""Run with python -m evaluation.run --output output/evaluation/policy.json."""
import argparse
import hashlib
import json
from pathlib import Path
import time
from core.evidence import classify, process_signals


def evaluate(path=None):
    path = Path(path or Path(__file__).with_name('policy_cases.json'))
    raw = path.read_bytes()
    cases = json.loads(raw)
    if not cases or len({case['id'] for case in cases}) != len(cases):
        raise ValueError('A nonempty, uniquely labelled dataset is required')
    started = time.perf_counter()
    counts = dict(true_positive=0, false_positive=0, true_negative=0, false_negative=0, unknown=0)
    results = []
    for case in cases:
        if type(case['needs_review']) is not bool:
            raise ValueError('Reference label must be a boolean')
        signals = process_signals(case['name'], case['path'], case['command'])
        result = classify(signals, case['signature'], case['inspected'])
        predicted = result['classification'] == 'corroborated_suspicion'
        expected = case['needs_review']
        counts['unknown'] += result['classification'] == 'unknown'
        counts[('true_positive' if predicted else 'false_negative') if expected
               else ('false_positive' if predicted else 'true_negative')] += 1
        results.append(dict(id=case['id'], expected_review=expected,
                            classification=result['classification'], predicted_review=predicted))
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None
    tp, fp, tn, fn = (counts[key] for key in ('true_positive', 'false_positive', 'true_negative', 'false_negative'))
    return dict(dataset_sha256=hashlib.sha256(raw).hexdigest(), cases=len(cases), counts=counts,
        precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn), false_positive_rate=ratio(fp, fp + tn),
        decision_coverage=1 - counts['unknown'] / len(cases),
        elapsed_seconds=time.perf_counter() - started, results=results,
        scope='Synthetic process-policy replay only; review labels are not malware ground truth.',
        limitations='Hand-authored regression fixtures, not independent detection effectiveness. Unknown positives count as missed review; no excluded unknowns or invented 100% guarantee.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = evaluate(args.dataset)
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
