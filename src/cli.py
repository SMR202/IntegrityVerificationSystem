"""
Command Line Interface for Merkle Tree Integrity Verification System.
Provides interactive menu for all system operations.
"""

import os
import sys
import time
import random
from typing import Optional, List
from tabulate import tabulate
from colorama import init, Fore, Style

from src.data_loader import DataLoader, Review
from src.merkle_tree import MerkleTree
from src.integrity import IntegrityVerifier
from src.tamper_detection import TamperDetector, TamperSimulator, TamperType
from src.performance import PerformanceMonitor

# Initialize colorama for Windows
init()


class CLI:
    """Command Line Interface for the Merkle Tree Integrity Verification System."""
    
    def __init__(self):
        self.loader: Optional[DataLoader] = None
        self.reviews: List[Review] = []
        self.tree: Optional[MerkleTree] = None
        self.verifier: IntegrityVerifier = IntegrityVerifier()
        self.detector: Optional[TamperDetector] = None
        self.monitor: PerformanceMonitor = PerformanceMonitor()
        self.dataset_name: str = ""
        
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print the application header."""
        print(Fore.CYAN + "=" * 70)
        print("   MERKLE TREE INTEGRITY VERIFICATION SYSTEM")
        print("   Amazon Review Dataset Analyzer")
        print("=" * 70 + Style.RESET_ALL)
        
        if self.tree:
            print(Fore.GREEN + f"   Dataset: {self.dataset_name} ({len(self.reviews):,} reviews)")
            print(f"   Root Hash: {self.tree.get_root_hash()[:32]}..." + Style.RESET_ALL)
        print()
    
    def print_menu(self):
        """Print the main menu."""
        menu = """
╔══════════════════════════════════════════════════════════════════════╗
║                           MAIN MENU                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  1. Load Dataset                    6. Simulate Tampering            ║
║  2. Build Merkle Tree               7. Run Performance Tests         ║
║  3. Display Dataset (Sample)        8. Generate Existence Proof      ║
║  4. Save Merkle Root                9. Compare Merkle Roots          ║
║  5. Verify Data Integrity          10. View Root History             ║
║                                                                      ║
║  0. Exit                                                             ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(menu)
    
    def get_input(self, prompt: str, default: str = None) -> str:
        """Get user input with optional default value."""
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "
        
        value = input(Fore.YELLOW + prompt + Style.RESET_ALL).strip()
        return value if value else (default or "")
    
    def confirm(self, prompt: str) -> bool:
        """Get yes/no confirmation from user."""
        response = self.get_input(f"{prompt} (y/n)", "n")
        return response.lower() in ['y', 'yes']
    
    def press_enter(self):
        """Wait for user to press Enter."""
        input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)
    
    def print_success(self, message: str):
        """Print success message."""
        print(Fore.GREEN + f"✓ {message}" + Style.RESET_ALL)
    
    def print_error(self, message: str):
        """Print error message."""
        print(Fore.RED + f"✗ {message}" + Style.RESET_ALL)
    
    def print_warning(self, message: str):
        """Print warning message."""
        print(Fore.YELLOW + f"⚠ {message}" + Style.RESET_ALL)
    
    def print_info(self, message: str):
        """Print info message."""
        print(Fore.BLUE + f"ℹ {message}" + Style.RESET_ALL)
    
    # ==================== Menu Actions ====================
    
    def action_load_dataset(self):
        """Load the Amazon review dataset."""
        print(Fore.CYAN + "\n=== LOAD DATASET ===" + Style.RESET_ALL)
        
        # List available files
        data_dir = "data"
        if os.path.exists(data_dir):
            files = [f for f in os.listdir(data_dir) if f.endswith(('.json', '.jsonl'))]
            if files:
                print("\nAvailable datasets:")
                for i, f in enumerate(files, 1):
                    print(f"  {i}. {f}")
            else:
                self.print_warning("No dataset files found in 'data/' directory")
                return
        else:
            self.print_error("Data directory not found")
            return
        
        filename = self.get_input("\nEnter dataset filename", files[0] if files else "")
        if not filename:
            return
        
        limit_str = self.get_input("Enter record limit (leave empty for all)", "")
        limit = int(limit_str) if limit_str.isdigit() else None
        
        try:
            self.loader = DataLoader()
            self.reviews = self.loader.load_reviews(filename, limit=limit, show_progress=True)
            self.dataset_name = filename.replace('.json', '').replace('.jsonl', '')
            
            # Show statistics
            stats = self.loader.get_dataset_stats()
            print("\n" + Fore.CYAN + "Dataset Statistics:" + Style.RESET_ALL)
            for key, value in stats.items():
                if isinstance(value, float):
                    print(f"  {key}: {value:.2f}")
                else:
                    print(f"  {key}: {value:,}" if isinstance(value, int) else f"  {key}: {value}")
            
            self.print_success(f"Loaded {len(self.reviews):,} reviews successfully!")
            
        except Exception as e:
            self.print_error(f"Failed to load dataset: {e}")
    
    def action_build_tree(self):
        """Build the Merkle Tree from loaded reviews."""
        print(Fore.CYAN + "\n=== BUILD MERKLE TREE ===" + Style.RESET_ALL)
        
        if not self.reviews:
            self.print_error("No dataset loaded. Please load a dataset first.")
            return
        
        try:
            self.tree = MerkleTree()
            root_hash = self.tree.build(self.reviews, show_progress=True)
            
            # Create tamper detector
            self.detector = TamperDetector(self.tree, self.reviews)
            
            self.print_success("Merkle Tree built successfully!")
            print(f"\n  Root Hash: {Fore.GREEN}{root_hash}{Style.RESET_ALL}")
            
        except Exception as e:
            self.print_error(f"Failed to build tree: {e}")
    
    def action_display_dataset(self):
        """Display dataset in tabular format."""
        print(Fore.CYAN + "\n=== DATASET VIEWER ===" + Style.RESET_ALL)
        
        if not self.reviews:
            self.print_error("No dataset loaded.")
            return
        
        n = self.get_input("Number of records to display", "10")
        n = int(n) if n.isdigit() else 10
        
        sample = self.reviews[:n]
        
        # Prepare table data
        table_data = []
        for r in sample:
            table_data.append([
                r.review_id[:12] + "...",
                r.asin,
                r.rating,
                (r.title[:30] + "...") if len(r.title) > 30 else r.title,
                "Yes" if r.verified else "No"
            ])
        
        headers = ["Review ID", "Product ID", "Rating", "Title", "Verified"]
        print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))
        
        print(f"\nShowing {n} of {len(self.reviews):,} reviews")
    
    def action_save_root(self):
        """Save the current Merkle root."""
        print(Fore.CYAN + "\n=== SAVE MERKLE ROOT ===" + Style.RESET_ALL)
        
        if not self.tree:
            self.print_error("No Merkle Tree built. Please build the tree first.")
            return
        
        notes = self.get_input("Enter notes for this root (optional)", "")
        
        try:
            record = self.verifier.save_root(
                root_hash=self.tree.get_root_hash(),
                dataset_name=self.dataset_name,
                record_count=len(self.reviews),
                tree_height=self.tree.height,
                notes=notes
            )
            
            self.print_success("Root saved successfully!")
            
        except Exception as e:
            self.print_error(f"Failed to save root: {e}")
    
    def action_verify_integrity(self):
        """Verify data integrity against stored root."""
        print(Fore.CYAN + "\n=== VERIFY DATA INTEGRITY ===" + Style.RESET_ALL)
        
        if not self.tree:
            self.print_error("No Merkle Tree built.")
            return
        
        result = self.verifier.verify_integrity(
            self.tree.get_root_hash(),
            self.dataset_name
        )
        
        if result['status'] == "INTEGRITY_VERIFIED":
            self.print_success(result['message'])
        elif result['status'] == "INTEGRITY_VIOLATED":
            self.print_error(result['message'])
        else:
            self.print_warning(result['message'])
        
        print(f"\n  Current Root: {result.get('current_hash', 'N/A')[:32]}...")
        if result.get('stored_hash'):
            print(f"  Stored Root:  {result['stored_hash'][:32]}...")
    
    def action_simulate_tampering(self):
        """Simulate various types of data tampering."""
        print(Fore.CYAN + "\n=== TAMPERING SIMULATION ===" + Style.RESET_ALL)
        
        if not self.tree or not self.detector:
            self.print_error("No Merkle Tree built.")
            return
        
        print("\nSelect tampering type:")
        print("  1. Modify a record")
        print("  2. Delete a record")
        print("  3. Insert a fake record")
        print("  4. Modify a single character")
        
        choice = self.get_input("Choice", "1")
        
        try:
            if choice == "1":
                idx = random.randint(0, len(self.reviews) - 1)
                tampered, desc = TamperSimulator.modify_record(self.reviews, index=idx)
                print(f"\n{Fore.YELLOW}Action: {desc}{Style.RESET_ALL}")
                
            elif choice == "2":
                idx = random.randint(0, len(self.reviews) - 1)
                tampered, desc = TamperSimulator.delete_record(self.reviews, index=idx)
                print(f"\n{Fore.YELLOW}Action: {desc}{Style.RESET_ALL}")
                
            elif choice == "3":
                tampered, desc = TamperSimulator.insert_record(self.reviews)
                print(f"\n{Fore.YELLOW}Action: {desc}{Style.RESET_ALL}")
                
            elif choice == "4":
                idx = random.randint(0, len(self.reviews) - 1)
                tampered, desc = TamperSimulator.modify_record(
                    self.reviews, index=idx, field="text"
                )
                print(f"\n{Fore.YELLOW}Action: Modified single character{Style.RESET_ALL}")
            else:
                self.print_error("Invalid choice")
                return
            
            # Detect tampering
            print("\nDetecting tampering...")
            result = self.detector.detect_tampering(tampered, show_progress=False)
            
            if result.detected:
                self.print_error(f"TAMPERING DETECTED!")
                print(f"  Type: {result.tamper_type.value}")
                print(f"  Message: {result.message}")
                print(f"\n  Original Root: {result.original_root[:32]}...")
                print(f"  Current Root:  {result.current_root[:32]}...")
            else:
                self.print_success("No tampering detected")
                
        except Exception as e:
            self.print_error(f"Simulation failed: {e}")
    
    def action_performance_tests(self):
        """Run performance benchmarks."""
        print(Fore.CYAN + "\n=== PERFORMANCE TESTS ===" + Style.RESET_ALL)
        
        if not self.reviews:
            self.print_error("No dataset loaded.")
            return
        
        print("\nSelect test type:")
        print("  1. Full benchmark (current dataset)")
        print("  2. Scaling test (multiple sizes)")
        print("  3. Proof latency test (1000 random proofs)")
        
        choice = self.get_input("Choice", "1")
        
        try:
            if choice == "1":
                metrics = self.monitor.run_full_benchmark(
                    self.dataset_name, self.reviews, show_progress=True
                )
                
                if self.confirm("Save metrics to file?"):
                    self.monitor.save_metrics(metrics)
                    
            elif choice == "2":
                sizes = self.get_input("Enter sizes (comma-separated)", "1000,10000,100000")
                size_list = [int(s.strip()) for s in sizes.split(",")]
                
                results = self.monitor.run_scaling_test(
                    f"{self.dataset_name}.json", sizes=size_list, show_progress=True
                )
                
                report = self.monitor.generate_report(results)
                print("\n" + report)
                
            elif choice == "3":
                if not self.tree:
                    self.print_error("Build Merkle Tree first.")
                    return
                
                print("\nRunning 1000 proof generations...")
                proof_metrics = self.monitor.measure_proof_performance(
                    self.tree, self.reviews, sample_size=1000
                )
                
                print(f"\n  Avg Generation Time: {proof_metrics['generation_avg_ms']:.4f} ms")
                print(f"  Min Generation Time: {proof_metrics['generation_min_ms']:.4f} ms")
                print(f"  Max Generation Time: {proof_metrics['generation_max_ms']:.4f} ms")
                print(f"  Avg Verification Time: {proof_metrics['verification_avg_ms']:.4f} ms")
                
                total = proof_metrics['generation_avg_ms'] + proof_metrics['verification_avg_ms']
                if total < 100:
                    self.print_success(f"Total proof time: {total:.4f} ms (< 100ms requirement)")
                else:
                    self.print_error(f"Total proof time: {total:.4f} ms (> 100ms requirement)")
                    
        except Exception as e:
            self.print_error(f"Performance test failed: {e}")
    
    def action_generate_proof(self):
        """Generate and verify existence proof for a review."""
        print(Fore.CYAN + "\n=== EXISTENCE PROOF ===" + Style.RESET_ALL)
        
        if not self.tree:
            self.print_error("No Merkle Tree built.")
            return
        
        print("\nOptions:")
        print("  1. Enter Review ID manually")
        print("  2. Select from sample reviews")
        print("  3. Search by Product ID (ASIN)")
        
        choice = self.get_input("Choice", "2")
        
        review_id = None
        
        if choice == "1":
            review_id = self.get_input("Enter Review ID")
            
        elif choice == "2":
            # Show sample reviews
            print("\nSample reviews:")
            sample = self.reviews[:10]
            for i, r in enumerate(sample, 1):
                print(f"  {i}. {r.review_id} - {r.title[:40]}...")
            
            idx = self.get_input("Select review number", "1")
            idx = int(idx) - 1 if idx.isdigit() else 0
            if 0 <= idx < len(sample):
                review_id = sample[idx].review_id
                
        elif choice == "3":
            asin = self.get_input("Enter Product ID (ASIN)")
            if self.loader:
                product_reviews = self.loader.get_reviews_by_product(asin)
                if product_reviews:
                    print(f"\nFound {len(product_reviews)} reviews for product {asin}:")
                    for i, r in enumerate(product_reviews[:5], 1):
                        print(f"  {i}. {r.review_id} - Rating: {r.rating}")
                    
                    idx = self.get_input("Select review number", "1")
                    idx = int(idx) - 1 if idx.isdigit() else 0
                    if 0 <= idx < len(product_reviews):
                        review_id = product_reviews[idx].review_id
                else:
                    self.print_warning(f"No reviews found for product {asin}")
                    return
        
        if not review_id:
            self.print_error("No review selected")
            return
        
        # Generate proof
        print(f"\nGenerating proof for: {review_id}")
        
        start = time.perf_counter()
        proof = self.tree.generate_proof(review_id)
        gen_time = (time.perf_counter() - start) * 1000
        
        if proof is None:
            self.print_error(f"Review {review_id} NOT FOUND in dataset")
            return
        
        self.print_success(f"Review {review_id} EXISTS in dataset")
        print(f"\n  Proof Length: {len(proof)} hashes")
        print(f"  Generation Time: {gen_time:.4f} ms")
        
        # Verify proof
        review = self.loader.get_review_by_id(review_id)
        if review:
            start = time.perf_counter()
            is_valid = self.tree.verify_proof(
                review_id, review.raw_hash, proof, self.tree.get_root_hash()
            )
            verify_time = (time.perf_counter() - start) * 1000
            
            if is_valid:
                self.print_success(f"Proof VERIFIED in {verify_time:.4f} ms")
            else:
                self.print_error("Proof verification FAILED")
        
        # Show proof path visualization
        if self.confirm("Show proof path visualization?"):
            print("\n" + self.tree.visualize_proof_path(proof, review.raw_hash))
    
    def action_compare_roots(self):
        """Compare current root with stored roots."""
        print(Fore.CYAN + "\n=== COMPARE MERKLE ROOTS ===" + Style.RESET_ALL)
        
        if not self.tree:
            self.print_error("No Merkle Tree built.")
            return
        
        # Load history
        history = self.verifier.get_root_history(self.dataset_name)
        
        if not history:
            self.print_warning("No stored roots found for comparison.")
            self.print_info("Save current root first to establish a baseline.")
            return
        
        print(f"\nCurrent Root: {self.tree.get_root_hash()[:32]}...")
        print(f"\nStored Roots ({len(history)} total):")
        
        for i, record in enumerate(history[-5:], 1):  # Last 5
            print(f"\n  [{i}] {record['created_at']}")
            print(f"      Hash: {record['root_hash'][:32]}...")
            print(f"      Records: {record['record_count']:,}")
            if record.get('notes'):
                print(f"      Notes: {record['notes']}")
        
        # Compare with latest
        result = self.verifier.compare_roots(self.tree.get_root_hash())
        
        print("\n" + "-" * 50)
        if result['integrity_verified']:
            self.print_success("Current root MATCHES stored root")
        elif result['integrity_verified'] is False:
            self.print_error("Current root DOES NOT MATCH stored root")
        else:
            self.print_warning(result['message'])
    
    def action_view_history(self):
        """View root history."""
        print(Fore.CYAN + "\n=== ROOT HISTORY ===" + Style.RESET_ALL)
        
        if not self.dataset_name:
            self.print_error("No dataset loaded.")
            return
        
        history = self.verifier.get_root_history(self.dataset_name)
        
        if not history:
            self.print_warning("No root history found.")
            return
        
        print(f"\nRoot history for: {self.dataset_name}")
        print(f"Total records: {len(history)}\n")
        
        table_data = []
        for i, record in enumerate(history, 1):
            table_data.append([
                i,
                record['created_at'][:19],
                record['root_hash'][:20] + "...",
                f"{record['record_count']:,}",
                record.get('notes', '')[:20]
            ])
        
        headers = ["#", "Created At", "Root Hash", "Records", "Notes"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    def run(self):
        """Main loop for the CLI."""
        while True:
            try:
                self.clear_screen()
                self.print_header()
                self.print_menu()
                
                choice = self.get_input("Enter your choice")
                
                if choice == "0":
                    print("\nGoodbye!")
                    break
                elif choice == "1":
                    self.action_load_dataset()
                elif choice == "2":
                    self.action_build_tree()
                elif choice == "3":
                    self.action_display_dataset()
                elif choice == "4":
                    self.action_save_root()
                elif choice == "5":
                    self.action_verify_integrity()
                elif choice == "6":
                    self.action_simulate_tampering()
                elif choice == "7":
                    self.action_performance_tests()
                elif choice == "8":
                    self.action_generate_proof()
                elif choice == "9":
                    self.action_compare_roots()
                elif choice == "10":
                    self.action_view_history()
                else:
                    self.print_error("Invalid choice. Please try again.")
                
                self.press_enter()
                
            except KeyboardInterrupt:
                print("\n\nOperation cancelled.")
                self.press_enter()
            except Exception as e:
                self.print_error(f"An error occurred: {e}")
                self.press_enter()


def main():
    """Entry point for the CLI application."""
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
