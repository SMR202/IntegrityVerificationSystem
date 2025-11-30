"""
Experiment Runner
Runs all experiments as specified in the project requirements and generates reports.

Experiments:
A. Static Integrity Verification - Build tree, store root, rebuild and compare
B. Tamper Simulation - Test modification, deletion, insertion detection
C. Proof Performance - Benchmark proof generation/verification for <100ms
D. Multi-Category Analysis - Compare performance across dataset sizes
"""

import os
import sys
import json
import time
import math
from datetime import datetime
from typing import Dict, Any, List

from src.data_loader import DataLoader
from src.merkle_tree import MerkleTree
from src.integrity import IntegrityVerifier
from src.tamper_detection import TamperDetector, TamperSimulator, TamperType
from src.performance import PerformanceMonitor


class ExperimentRunner:
    """Runs all experiments and generates comprehensive reports."""
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        self.results = {}
        
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
    
    def run_all_experiments(self, dataset_file: str = "Video_Games.json"):
        """Run all experiments and generate a comprehensive report."""
        print("=" * 70)
        print("  MERKLE TREE INTEGRITY VERIFICATION - EXPERIMENT SUITE")
        print("=" * 70)
        print(f"Dataset: {dataset_file}")
        print(f"Started: {datetime.now().isoformat()}")
        print("=" * 70)
        
        self.results = {
            "experiment_metadata": {
                "dataset": dataset_file,
                "started_at": datetime.now().isoformat(),
                "python_version": sys.version
            }
        }
        
        # Run all experiments
        self.experiment_a_static_verification(dataset_file)
        self.experiment_b_tamper_simulation(dataset_file)
        self.experiment_c_proof_performance(dataset_file)
        self.experiment_d_scalability_analysis(dataset_file)
        
        # Generate final report
        self.results["experiment_metadata"]["completed_at"] = datetime.now().isoformat()
        report_path = self.save_experiment_report()
        
        print("\n" + "=" * 70)
        print("  ALL EXPERIMENTS COMPLETED!")
        print("=" * 70)
        print(f"Report saved to: {report_path}")
        
        return self.results
    
    def experiment_a_static_verification(self, dataset_file: str):
        """
        Experiment A: Static Integrity Verification
        
        Steps:
        1. Load dataset
        2. Build Merkle Tree
        3. Store root hash
        4. Rebuild tree and compare root
        """
        print("\n" + "=" * 70)
        print("  EXPERIMENT A: Static Integrity Verification")
        print("=" * 70)
        
        loader = DataLoader()
        
        # Test with different sizes
        test_sizes = [1000, 10000, 100000]
        results = {"tests": [], "summary": {}}
        
        for size in test_sizes:
            print(f"\nTesting with {size:,} records...")
            
            # Load data
            reviews = loader.load_reviews(dataset_file, limit=size, show_progress=False)
            actual_size = len(reviews)
            
            # Build tree
            tree1 = MerkleTree()
            start = time.perf_counter()
            root1 = tree1.build(reviews, show_progress=False)
            build_time = time.perf_counter() - start
            
            # Store root
            verifier = IntegrityVerifier()
            verifier.save_root(
                root_hash=root1,
                dataset_name=f"exp_a_{actual_size}",
                record_count=actual_size,
                tree_height=tree1.height
            )
            
            # Rebuild tree
            tree2 = MerkleTree()
            start = time.perf_counter()
            root2 = tree2.build(reviews, show_progress=False)
            rebuild_time = time.perf_counter() - start
            
            # Compare
            roots_match = root1 == root2
            
            test_result = {
                "size": actual_size,
                "build_time_s": round(build_time, 4),
                "rebuild_time_s": round(rebuild_time, 4),
                "tree_height": tree1.height,
                "total_nodes": tree1.total_nodes,
                "root_hash_first_32": root1[:32],
                "roots_match": roots_match,
                "status": "PASS" if roots_match else "FAIL"
            }
            results["tests"].append(test_result)
            
            status = "✓ PASSED" if roots_match else "✗ FAILED"
            print(f"  Records: {actual_size:,}")
            print(f"  Build time: {build_time:.4f}s")
            print(f"  Root hash: {root1[:32]}...")
            print(f"  Roots match: {status}")
        
        # Summary
        all_passed = all(t["status"] == "PASS" for t in results["tests"])
        results["summary"] = {
            "total_tests": len(results["tests"]),
            "passed": sum(1 for t in results["tests"] if t["status"] == "PASS"),
            "failed": sum(1 for t in results["tests"] if t["status"] == "FAIL"),
            "overall_status": "PASS" if all_passed else "FAIL"
        }
        
        self.results["experiment_a"] = results
        
        print(f"\n  Summary: {results['summary']['passed']}/{results['summary']['total_tests']} tests passed")
        print(f"  Overall: {results['summary']['overall_status']}")
        
    def experiment_b_tamper_simulation(self, dataset_file: str):
        """
        Experiment B: Tamper Detection Simulation
        
        Tests:
        1. Record modification detection
        2. Record deletion detection
        3. Record insertion detection
        4. No false positives
        """
        print("\n" + "=" * 70)
        print("  EXPERIMENT B: Tamper Detection Simulation")
        print("=" * 70)
        
        loader = DataLoader()
        reviews = loader.load_reviews(dataset_file, limit=10000, show_progress=False)
        
        tree = MerkleTree()
        original_root = tree.build(reviews, show_progress=False)
        detector = TamperDetector(tree, reviews)
        
        results = {"tests": [], "summary": {}}
        
        print(f"\nOriginal dataset: {len(reviews):,} records")
        print(f"Original root: {original_root[:32]}...")
        
        # Test 1: No tampering (baseline)
        print("\n1. Testing baseline (no tampering)...")
        result = detector.detect_tampering(reviews, show_progress=False)
        test1 = {
            "test": "no_tampering",
            "tampering_detected": result.detected,
            "expected_detected": False,
            "status": "PASS" if not result.detected else "FAIL"
        }
        results["tests"].append(test1)
        print(f"   Tampering detected: {result.detected}")
        print(f"   Status: {'✓ PASS' if test1['status'] == 'PASS' else '✗ FAIL'}")
        
        # Test 2: Modification
        print("\n2. Testing modification detection...")
        for pos in [0, len(reviews)//2, len(reviews)-1]:
            tampered, desc = TamperSimulator.modify_record(reviews, index=pos)
            result = detector.detect_tampering(tampered, show_progress=False)
            
            test = {
                "test": f"modification_pos_{pos}",
                "position": pos,
                "tampering_detected": result.detected,
                "detected_type": result.tamper_type.value,
                "expected_type": "MODIFICATION",
                "status": "PASS" if result.detected and result.tamper_type == TamperType.MODIFICATION else "FAIL"
            }
            results["tests"].append(test)
            print(f"   Position {pos}: Detected={result.detected}, Type={result.tamper_type.value}")
        
        # Test 3: Deletion
        print("\n3. Testing deletion detection...")
        for pos in [0, len(reviews)//2, len(reviews)-1]:
            tampered, desc = TamperSimulator.delete_record(reviews, index=pos)
            result = detector.detect_tampering(tampered, show_progress=False)
            
            test = {
                "test": f"deletion_pos_{pos}",
                "position": pos,
                "tampering_detected": result.detected,
                "detected_type": result.tamper_type.value,
                "expected_type": "DELETION",
                "status": "PASS" if result.detected and result.tamper_type == TamperType.DELETION else "FAIL"
            }
            results["tests"].append(test)
            print(f"   Position {pos}: Detected={result.detected}, Type={result.tamper_type.value}")
        
        # Test 4: Insertion
        print("\n4. Testing insertion detection...")
        for pos in [0, len(reviews)//2, None]:  # None = append at end
            tampered, desc = TamperSimulator.insert_record(reviews, index=pos)
            result = detector.detect_tampering(tampered, show_progress=False)
            
            test = {
                "test": f"insertion_pos_{pos}",
                "position": pos if pos else "end",
                "tampering_detected": result.detected,
                "detected_type": result.tamper_type.value,
                "expected_type": "INSERTION",
                "status": "PASS" if result.detected and result.tamper_type == TamperType.INSERTION else "FAIL"
            }
            results["tests"].append(test)
            pos_str = str(pos) if pos else "end"
            print(f"   Position {pos_str}: Detected={result.detected}, Type={result.tamper_type.value}")
        
        # Summary
        all_passed = all(t["status"] == "PASS" for t in results["tests"])
        results["summary"] = {
            "total_tests": len(results["tests"]),
            "passed": sum(1 for t in results["tests"] if t["status"] == "PASS"),
            "failed": sum(1 for t in results["tests"] if t["status"] == "FAIL"),
            "overall_status": "PASS" if all_passed else "FAIL"
        }
        
        self.results["experiment_b"] = results
        
        print(f"\n  Summary: {results['summary']['passed']}/{results['summary']['total_tests']} tests passed")
        print(f"  Overall: {results['summary']['overall_status']}")
        
    def experiment_c_proof_performance(self, dataset_file: str):
        """
        Experiment C: Proof Generation & Verification Performance
        
        Requirement: Proof verification must complete in < 100ms
        """
        print("\n" + "=" * 70)
        print("  EXPERIMENT C: Proof Performance Benchmarking")
        print("=" * 70)
        
        loader = DataLoader()
        
        # Test with different sizes
        test_sizes = [1000, 10000, 100000, 500000, 1000000]
        results = {"tests": [], "summary": {}}
        
        for size in test_sizes:
            print(f"\nTesting with {size:,} records...")
            
            reviews = loader.load_reviews(dataset_file, limit=size, show_progress=False)
            actual_size = len(reviews)
            
            if actual_size < size:
                print(f"  (Dataset only has {actual_size:,} records)")
            
            tree = MerkleTree()
            tree.build(reviews, show_progress=False)
            
            # Run proof benchmarks
            sample_size = min(100, actual_size)
            generation_times = []
            verification_times = []
            total_times = []
            
            sample_indices = [i * (actual_size // sample_size) for i in range(sample_size)]
            
            for idx in sample_indices:
                review = reviews[idx]
                
                # Generation time
                start = time.perf_counter()
                proof = tree.generate_proof(review.review_id)
                gen_time = (time.perf_counter() - start) * 1000  # Convert to ms
                
                # Verification time
                start = time.perf_counter()
                is_valid = tree.verify_proof(
                    review.review_id,
                    review.raw_hash,
                    proof,
                    tree.get_root_hash()
                )
                ver_time = (time.perf_counter() - start) * 1000
                
                generation_times.append(gen_time)
                verification_times.append(ver_time)
                total_times.append(gen_time + ver_time)
            
            avg_total = sum(total_times) / len(total_times)
            max_total = max(total_times)
            meets_requirement = max_total < 100
            
            test_result = {
                "size": actual_size,
                "sample_size": sample_size,
                "tree_height": tree.height,
                "proof_length": len(proof) if proof else 0,
                "generation_avg_ms": round(sum(generation_times)/len(generation_times), 4),
                "generation_max_ms": round(max(generation_times), 4),
                "verification_avg_ms": round(sum(verification_times)/len(verification_times), 4),
                "verification_max_ms": round(max(verification_times), 4),
                "total_avg_ms": round(avg_total, 4),
                "total_max_ms": round(max_total, 4),
                "requirement_100ms": "PASS" if meets_requirement else "FAIL",
                "status": "PASS" if meets_requirement else "FAIL"
            }
            results["tests"].append(test_result)
            
            status = "✓" if meets_requirement else "✗"
            print(f"  Records: {actual_size:,}")
            print(f"  Proof length: {test_result['proof_length']} hashes (log₂({actual_size})={math.log2(actual_size):.1f})")
            print(f"  Avg proof time: {avg_total:.4f} ms")
            print(f"  Max proof time: {max_total:.4f} ms")
            print(f"  <100ms requirement: {status} {'PASSED' if meets_requirement else 'FAILED'}")
        
        # Summary
        all_passed = all(t["status"] == "PASS" for t in results["tests"])
        results["summary"] = {
            "total_tests": len(results["tests"]),
            "passed": sum(1 for t in results["tests"] if t["status"] == "PASS"),
            "failed": sum(1 for t in results["tests"] if t["status"] == "FAIL"),
            "overall_status": "PASS" if all_passed else "FAIL",
            "fastest_avg_ms": min(t["total_avg_ms"] for t in results["tests"]),
            "slowest_avg_ms": max(t["total_avg_ms"] for t in results["tests"])
        }
        
        self.results["experiment_c"] = results
        
        print(f"\n  Summary: {results['summary']['passed']}/{results['summary']['total_tests']} tests passed")
        print(f"  Fastest avg: {results['summary']['fastest_avg_ms']:.4f} ms")
        print(f"  Slowest avg: {results['summary']['slowest_avg_ms']:.4f} ms")
        print(f"  Overall: {results['summary']['overall_status']}")
        
    def experiment_d_scalability_analysis(self, dataset_file: str):
        """
        Experiment D: Scalability Analysis
        
        Analyzes how performance scales with dataset size.
        """
        print("\n" + "=" * 70)
        print("  EXPERIMENT D: Scalability Analysis")
        print("=" * 70)
        
        loader = DataLoader()
        
        sizes = [100, 500, 1000, 5000, 10000, 50000, 100000]
        results = {"tests": [], "summary": {}}
        
        print(f"\nAnalyzing scalability across {len(sizes)} different sizes...")
        print("-" * 70)
        print(f"{'Size':>10} {'Build(s)':>12} {'Hash/s':>12} {'Proof(ms)':>12} {'Height':>8}")
        print("-" * 70)
        
        for size in sizes:
            reviews = loader.load_reviews(dataset_file, limit=size, show_progress=False)
            actual_size = len(reviews)
            
            if actual_size < size * 0.9:  # Less than 90% of requested
                print(f"  (Stopping - dataset limit reached at {actual_size:,})")
                break
            
            # Build tree
            tree = MerkleTree()
            start = time.perf_counter()
            tree.build(reviews, show_progress=False)
            build_time = time.perf_counter() - start
            
            # Calculate throughput
            hashes_per_second = actual_size / build_time if build_time > 0 else 0
            
            # Measure proof time
            sample_review = reviews[actual_size // 2]
            start = time.perf_counter()
            proof = tree.generate_proof(sample_review.review_id)
            tree.verify_proof(
                sample_review.review_id,
                sample_review.raw_hash,
                proof,
                tree.get_root_hash()
            )
            proof_time = (time.perf_counter() - start) * 1000
            
            test_result = {
                "size": actual_size,
                "build_time_s": round(build_time, 4),
                "hashes_per_second": round(hashes_per_second, 2),
                "proof_time_ms": round(proof_time, 4),
                "tree_height": tree.height,
                "total_nodes": tree.total_nodes
            }
            results["tests"].append(test_result)
            
            print(f"{actual_size:>10,} {build_time:>12.4f} {hashes_per_second:>12,.0f} {proof_time:>12.4f} {tree.height:>8}")
        
        # Summary - analyze scalability
        if len(results["tests"]) >= 2:
            first = results["tests"][0]
            last = results["tests"][-1]
            size_ratio = last["size"] / first["size"]
            time_ratio = last["build_time_s"] / first["build_time_s"] if first["build_time_s"] > 0 else 0
            
            # For O(n log n), the ratio should be approximately n*log(n) / m*log(m)
            expected_ratio = (last["size"] * math.log2(last["size"])) / \
                           (first["size"] * math.log2(first["size"])) if first["size"] > 1 else 0
            
            results["summary"] = {
                "total_sizes_tested": len(results["tests"]),
                "size_range": f"{results['tests'][0]['size']:,} to {results['tests'][-1]['size']:,}",
                "build_time_range": f"{results['tests'][0]['build_time_s']:.4f}s to {results['tests'][-1]['build_time_s']:.4f}s",
                "size_growth_factor": round(size_ratio, 2),
                "time_growth_factor": round(time_ratio, 2),
                "expected_nlogn_factor": round(expected_ratio, 2),
                "complexity_assessment": "O(n log n)" if time_ratio <= expected_ratio * 1.5 else "Potentially higher"
            }
        
        self.results["experiment_d"] = results
        
        print("-" * 70)
        print(f"\n  Summary:")
        print(f"    Sizes tested: {results['summary']['size_range']}")
        print(f"    Size growth: {results['summary']['size_growth_factor']}x")
        print(f"    Time growth: {results['summary']['time_growth_factor']}x")
        print(f"    Expected (n log n): ~{results['summary']['expected_nlogn_factor']}x")
        print(f"    Complexity: {results['summary']['complexity_assessment']}")
        
    def save_experiment_report(self) -> str:
        """Save the experiment results to a JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"experiment_report_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        
        return filepath
    
    def generate_text_report(self) -> str:
        """Generate a human-readable text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("MERKLE TREE INTEGRITY VERIFICATION SYSTEM")
        lines.append("EXPERIMENT REPORT")
        lines.append("=" * 70)
        lines.append("")
        
        meta = self.results.get("experiment_metadata", {})
        lines.append(f"Dataset: {meta.get('dataset', 'N/A')}")
        lines.append(f"Started: {meta.get('started_at', 'N/A')}")
        lines.append(f"Completed: {meta.get('completed_at', 'N/A')}")
        lines.append("")
        
        # Experiment A
        if "experiment_a" in self.results:
            exp = self.results["experiment_a"]
            lines.append("-" * 70)
            lines.append("EXPERIMENT A: Static Integrity Verification")
            lines.append("-" * 70)
            lines.append(f"Status: {exp['summary']['overall_status']}")
            lines.append(f"Tests: {exp['summary']['passed']}/{exp['summary']['total_tests']} passed")
            lines.append("")
        
        # Experiment B
        if "experiment_b" in self.results:
            exp = self.results["experiment_b"]
            lines.append("-" * 70)
            lines.append("EXPERIMENT B: Tamper Detection")
            lines.append("-" * 70)
            lines.append(f"Status: {exp['summary']['overall_status']}")
            lines.append(f"Tests: {exp['summary']['passed']}/{exp['summary']['total_tests']} passed")
            lines.append("")
        
        # Experiment C
        if "experiment_c" in self.results:
            exp = self.results["experiment_c"]
            lines.append("-" * 70)
            lines.append("EXPERIMENT C: Proof Performance")
            lines.append("-" * 70)
            lines.append(f"Status: {exp['summary']['overall_status']}")
            lines.append(f"Requirement: < 100ms")
            lines.append(f"Fastest: {exp['summary']['fastest_avg_ms']:.4f} ms")
            lines.append(f"Slowest: {exp['summary']['slowest_avg_ms']:.4f} ms")
            lines.append("")
        
        # Experiment D
        if "experiment_d" in self.results:
            exp = self.results["experiment_d"]
            lines.append("-" * 70)
            lines.append("EXPERIMENT D: Scalability Analysis")
            lines.append("-" * 70)
            lines.append(f"Sizes tested: {exp['summary']['size_range']}")
            lines.append(f"Complexity: {exp['summary']['complexity_assessment']}")
            lines.append("")
        
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        
        return "\n".join(lines)


def main():
    """Run all experiments."""
    runner = ExperimentRunner()
    results = runner.run_all_experiments("Video_Games.json")
    
    # Print text report
    print("\n")
    print(runner.generate_text_report())
    
    return results


if __name__ == "__main__":
    main()
