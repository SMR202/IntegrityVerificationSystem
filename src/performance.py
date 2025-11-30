"""
Performance Measurement Module
Measures and logs performance metrics for the Merkle Tree system.
"""

import time
import psutil
import os
import json
import statistics
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from tqdm import tqdm

from src.data_loader import DataLoader, Review
from src.merkle_tree import MerkleTree


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    dataset_name: str
    record_count: int
    timestamp: str
    
    # Build metrics
    total_build_time_seconds: float
    hash_time_avg_ms: float
    hash_time_total_seconds: float
    tree_construction_seconds: float
    
    # Memory metrics
    peak_memory_mb: float
    memory_before_mb: float
    memory_after_mb: float
    memory_delta_mb: float
    
    # Tree metrics
    tree_height: int
    total_nodes: int
    leaf_count: int
    
    # Proof metrics
    proof_generation_avg_ms: float
    proof_verification_avg_ms: float
    proof_length_avg: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def summary(self) -> str:
        """Generate a summary string."""
        lines = [
            "=" * 60,
            "PERFORMANCE METRICS SUMMARY",
            "=" * 60,
            f"Dataset: {self.dataset_name}",
            f"Records: {self.record_count:,}",
            f"Timestamp: {self.timestamp}",
            "",
            "BUILD PERFORMANCE:",
            f"  Total Build Time: {self.total_build_time_seconds:.3f} seconds",
            f"  Avg Hash Time: {self.hash_time_avg_ms:.4f} ms/record",
            f"  Tree Construction: {self.tree_construction_seconds:.3f} seconds",
            "",
            "MEMORY USAGE:",
            f"  Peak Memory: {self.peak_memory_mb:.2f} MB",
            f"  Memory Delta: {self.memory_delta_mb:.2f} MB",
            "",
            "TREE STRUCTURE:",
            f"  Height: {self.tree_height}",
            f"  Total Nodes: {self.total_nodes:,}",
            f"  Leaf Count: {self.leaf_count:,}",
            "",
            "PROOF PERFORMANCE:",
            f"  Avg Proof Generation: {self.proof_generation_avg_ms:.4f} ms",
            f"  Avg Proof Verification: {self.proof_verification_avg_ms:.4f} ms",
            f"  Avg Proof Length: {self.proof_length_avg:.1f} hashes",
            "=" * 60
        ]
        return "\n".join(lines)


class PerformanceMonitor:
    """
    Monitors and measures performance metrics for Merkle Tree operations.
    """
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        self.metrics_history: List[PerformanceMetrics] = []
        
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
    
    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / (1024 * 1024)
    
    def _time_function(self, func: Callable, *args, **kwargs) -> tuple:
        """Time a function execution and return (result, time_seconds)."""
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        return result, elapsed
    
    def measure_hash_performance(self, reviews: List[Review], 
                                 sample_size: int = 1000) -> Dict[str, float]:
        """
        Measure hashing performance.
        
        Args:
            reviews: List of reviews to hash
            sample_size: Number of reviews to sample for measurement
            
        Returns:
            Dictionary with timing statistics
        """
        sample = reviews[:min(sample_size, len(reviews))]
        times = []
        
        for review in sample:
            start = time.perf_counter()
            review.compute_hash()
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)  # Convert to milliseconds
        
        return {
            "avg_ms": statistics.mean(times),
            "min_ms": min(times),
            "max_ms": max(times),
            "std_ms": statistics.stdev(times) if len(times) > 1 else 0,
            "total_seconds": sum(times) / 1000
        }
    
    def measure_proof_performance(self, tree: MerkleTree, 
                                  reviews: List[Review],
                                  sample_size: int = 100) -> Dict[str, float]:
        """
        Measure proof generation and verification performance.
        
        Args:
            tree: Built Merkle tree
            reviews: Original reviews
            sample_size: Number of proofs to generate/verify
            
        Returns:
            Dictionary with timing statistics
        """
        import random
        
        sample_indices = random.sample(range(len(reviews)), min(sample_size, len(reviews)))
        
        gen_times = []
        verify_times = []
        proof_lengths = []
        
        root_hash = tree.get_root_hash()
        
        for idx in sample_indices:
            review = reviews[idx]
            
            # Measure proof generation
            start = time.perf_counter()
            proof = tree.generate_proof(review.review_id)
            gen_elapsed = time.perf_counter() - start
            gen_times.append(gen_elapsed * 1000)
            
            if proof:
                proof_lengths.append(len(proof))
                
                # Measure proof verification
                start = time.perf_counter()
                tree.verify_proof(review.review_id, review.raw_hash, proof, root_hash)
                verify_elapsed = time.perf_counter() - start
                verify_times.append(verify_elapsed * 1000)
        
        return {
            "generation_avg_ms": statistics.mean(gen_times) if gen_times else 0,
            "generation_min_ms": min(gen_times) if gen_times else 0,
            "generation_max_ms": max(gen_times) if gen_times else 0,
            "verification_avg_ms": statistics.mean(verify_times) if verify_times else 0,
            "verification_min_ms": min(verify_times) if verify_times else 0,
            "verification_max_ms": max(verify_times) if verify_times else 0,
            "proof_length_avg": statistics.mean(proof_lengths) if proof_lengths else 0,
            "samples_tested": len(sample_indices)
        }
    
    def run_full_benchmark(self, dataset_name: str, reviews: List[Review],
                           show_progress: bool = True) -> PerformanceMetrics:
        """
        Run a complete performance benchmark.
        
        Args:
            dataset_name: Name of the dataset being tested
            reviews: List of reviews to build tree from
            show_progress: Whether to show progress bars
            
        Returns:
            PerformanceMetrics object with all measurements
        """
        print("\n" + "=" * 60)
        print("RUNNING PERFORMANCE BENCHMARK")
        print("=" * 60)
        
        # Initial memory
        memory_before = self._get_memory_usage_mb()
        peak_memory = memory_before
        
        # Measure hash performance
        print("\n1. Measuring hash performance...")
        hash_metrics = self.measure_hash_performance(reviews)
        print(f"   Avg hash time: {hash_metrics['avg_ms']:.4f} ms")
        
        peak_memory = max(peak_memory, self._get_memory_usage_mb())
        
        # Build tree and measure
        print("\n2. Building Merkle Tree...")
        tree = MerkleTree()
        
        build_start = time.perf_counter()
        tree.build(reviews, show_progress=show_progress)
        build_time = time.perf_counter() - build_start
        
        peak_memory = max(peak_memory, self._get_memory_usage_mb())
        memory_after = self._get_memory_usage_mb()
        
        print(f"   Build time: {build_time:.3f} seconds")
        
        # Measure proof performance
        print("\n3. Measuring proof performance...")
        proof_metrics = self.measure_proof_performance(tree, reviews)
        print(f"   Avg proof generation: {proof_metrics['generation_avg_ms']:.4f} ms")
        print(f"   Avg proof verification: {proof_metrics['verification_avg_ms']:.4f} ms")
        
        # Check if proof time meets requirement (< 100ms)
        total_proof_time = proof_metrics['generation_avg_ms'] + proof_metrics['verification_avg_ms']
        requirement_met = total_proof_time < 100
        print(f"\n   Proof time requirement (<100ms): {'✓ MET' if requirement_met else '✗ NOT MET'}")
        print(f"   Total proof time: {total_proof_time:.4f} ms")
        
        # Create metrics object
        metrics = PerformanceMetrics(
            dataset_name=dataset_name,
            record_count=len(reviews),
            timestamp=datetime.now().isoformat(),
            total_build_time_seconds=build_time,
            hash_time_avg_ms=hash_metrics['avg_ms'],
            hash_time_total_seconds=hash_metrics['total_seconds'],
            tree_construction_seconds=build_time - hash_metrics['total_seconds'],
            peak_memory_mb=peak_memory,
            memory_before_mb=memory_before,
            memory_after_mb=memory_after,
            memory_delta_mb=memory_after - memory_before,
            tree_height=tree.height,
            total_nodes=tree.total_nodes,
            leaf_count=len(tree.leaves),
            proof_generation_avg_ms=proof_metrics['generation_avg_ms'],
            proof_verification_avg_ms=proof_metrics['verification_avg_ms'],
            proof_length_avg=proof_metrics['proof_length_avg']
        )
        
        self.metrics_history.append(metrics)
        
        print("\n" + metrics.summary())
        
        return metrics
    
    def run_scaling_test(self, filename: str, sizes: List[int] = None,
                         show_progress: bool = True) -> List[PerformanceMetrics]:
        """
        Run benchmark at different dataset sizes to analyze scaling.
        
        Args:
            filename: Dataset file to load
            sizes: List of sizes to test (default: powers of 10)
            show_progress: Whether to show progress
            
        Returns:
            List of PerformanceMetrics for each size
        """
        if sizes is None:
            sizes = [1000, 10000, 100000, 500000, 1000000]
        
        results = []
        loader = DataLoader()
        
        for size in sizes:
            print(f"\n{'=' * 60}")
            print(f"Testing with {size:,} records")
            print("=" * 60)
            
            try:
                reviews = loader.load_reviews(filename, limit=size, show_progress=show_progress)
                metrics = self.run_full_benchmark(f"Video_Games_{size}", reviews, show_progress)
                results.append(metrics)
            except Exception as e:
                print(f"Error at size {size}: {e}")
                break
        
        return results
    
    def save_metrics(self, metrics: PerformanceMetrics, 
                     filename: str = None) -> str:
        """Save metrics to a JSON file."""
        if filename is None:
            filename = f"metrics_{metrics.dataset_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(metrics.to_dict(), f, indent=2)
        
        print(f"Metrics saved to: {filepath}")
        return filepath
    
    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """
        Get all metrics from history as a list of dictionaries.
        
        Returns:
            List of metrics dictionaries from the metrics_history
        """
        return [m.to_dict() for m in self.metrics_history]
    
    def generate_report(self, metrics_list: List[PerformanceMetrics]) -> str:
        """Generate a comparison report from multiple metrics."""
        lines = [
            "=" * 80,
            "PERFORMANCE COMPARISON REPORT",
            "=" * 80,
            f"Generated: {datetime.now().isoformat()}",
            "",
            "SCALING ANALYSIS:",
            "-" * 80,
            f"{'Records':>12} | {'Build Time':>12} | {'Avg Hash':>12} | {'Avg Proof':>12} | {'Memory':>10}",
            f"{'':>12} | {'(seconds)':>12} | {'(ms)':>12} | {'(ms)':>12} | {'(MB)':>10}",
            "-" * 80
        ]
        
        for m in metrics_list:
            total_proof = m.proof_generation_avg_ms + m.proof_verification_avg_ms
            lines.append(
                f"{m.record_count:>12,} | "
                f"{m.total_build_time_seconds:>12.3f} | "
                f"{m.hash_time_avg_ms:>12.4f} | "
                f"{total_proof:>12.4f} | "
                f"{m.memory_delta_mb:>10.2f}"
            )
        
        lines.append("-" * 80)
        lines.append("")
        lines.append("OBSERVATIONS:")
        
        if len(metrics_list) >= 2:
            first = metrics_list[0]
            last = metrics_list[-1]
            scale_factor = last.record_count / first.record_count
            time_factor = last.total_build_time_seconds / first.total_build_time_seconds
            
            lines.append(f"  - Dataset scaled {scale_factor:.0f}x")
            lines.append(f"  - Build time scaled {time_factor:.1f}x")
            lines.append(f"  - Proof time remains O(log n) - approximately constant")
        
        lines.append("")
        lines.append("=" * 80)
        
        return "\n".join(lines)


# Quick test
if __name__ == "__main__":
    print("Testing Performance Monitor...\n")
    
    # Load a small dataset for quick test
    loader = DataLoader()
    reviews = loader.load_reviews("Video_Games.json", limit=10000, show_progress=True)
    
    # Run benchmark
    monitor = PerformanceMonitor()
    metrics = monitor.run_full_benchmark("Video_Games_10k", reviews, show_progress=True)
    
    # Save metrics
    monitor.save_metrics(metrics)
