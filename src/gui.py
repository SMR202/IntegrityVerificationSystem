"""
Graphical User Interface for Merkle Tree Integrity Verification System.
Built with CustomTkinter for a modern look.
"""

import os
import threading
import time
import random
from typing import Optional, List
import customtkinter as ctk
from tkinter import messagebox, scrolledtext
import tkinter as tk

from src.data_loader import DataLoader, Review
from src.merkle_tree import MerkleTree
from src.integrity import IntegrityVerifier
from src.tamper_detection import TamperDetector, TamperSimulator
from src.performance import PerformanceMonitor


# Set appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class MerkleTreeGUI(ctk.CTk):
    """Main GUI application for the Merkle Tree Integrity Verification System."""
    
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title("Merkle Tree Integrity Verification System")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        # Data
        self.loader: Optional[DataLoader] = None
        self.reviews: List[Review] = []
        self.tree: Optional[MerkleTree] = None
        self.verifier = IntegrityVerifier()
        self.detector: Optional[TamperDetector] = None
        self.monitor = PerformanceMonitor()
        self.dataset_name = ""
        
        # Setup UI
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the user interface."""
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self._create_sidebar()
        
        # Main content area
        self._create_main_area()
        
        # Status bar
        self._create_status_bar()
        
    def _create_sidebar(self):
        """Create the sidebar with action buttons."""
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_rowconfigure(12, weight=1)
        
        # Logo/Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="🌳 Merkle Tree\nVerification",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Buttons
        button_config = {"width": 180, "height": 35, "corner_radius": 8}
        
        self.btn_load = ctk.CTkButton(
            self.sidebar, text="📂 Load Dataset",
            command=self._action_load, **button_config
        )
        self.btn_load.grid(row=1, column=0, padx=10, pady=5)
        
        self.btn_build = ctk.CTkButton(
            self.sidebar, text="🔨 Build Tree",
            command=self._action_build, **button_config
        )
        self.btn_build.grid(row=2, column=0, padx=10, pady=5)
        
        self.btn_view = ctk.CTkButton(
            self.sidebar, text="📊 View Dataset",
            command=self._action_view, **button_config
        )
        self.btn_view.grid(row=3, column=0, padx=10, pady=5)
        
        # Separator
        sep1 = ctk.CTkLabel(self.sidebar, text="─" * 20, font=ctk.CTkFont(size=10))
        sep1.grid(row=4, column=0, pady=5)
        
        self.btn_save = ctk.CTkButton(
            self.sidebar, text="💾 Save Root",
            command=self._action_save, **button_config
        )
        self.btn_save.grid(row=5, column=0, padx=10, pady=5)
        
        self.btn_verify = ctk.CTkButton(
            self.sidebar, text="✓ Verify Integrity",
            command=self._action_verify, **button_config
        )
        self.btn_verify.grid(row=6, column=0, padx=10, pady=5)
        
        self.btn_proof = ctk.CTkButton(
            self.sidebar, text="🔍 Generate Proof",
            command=self._action_proof, **button_config
        )
        self.btn_proof.grid(row=7, column=0, padx=10, pady=5)
        
        # Separator
        sep2 = ctk.CTkLabel(self.sidebar, text="─" * 20, font=ctk.CTkFont(size=10))
        sep2.grid(row=8, column=0, pady=5)
        
        self.btn_tamper = ctk.CTkButton(
            self.sidebar, text="⚠️ Simulate Tamper",
            command=self._action_tamper, **button_config,
            fg_color="#B22222", hover_color="#8B0000"
        )
        self.btn_tamper.grid(row=9, column=0, padx=10, pady=5)
        
        self.btn_benchmark = ctk.CTkButton(
            self.sidebar, text="⏱️ Performance Test",
            command=self._action_benchmark, **button_config
        )
        self.btn_benchmark.grid(row=10, column=0, padx=10, pady=5)
        
        # Theme toggle
        self.appearance_mode = ctk.CTkOptionMenu(
            self.sidebar,
            values=["Dark", "Light", "System"],
            command=self._change_appearance,
            width=180
        )
        self.appearance_mode.grid(row=13, column=0, padx=10, pady=10)
        
    def _create_main_area(self):
        """Create the main content area."""
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # Info panel
        self.info_frame = ctk.CTkFrame(self.main_frame, height=100)
        self.info_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.info_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Info labels
        self._create_info_card(self.info_frame, 0, "Dataset", "None")
        self._create_info_card(self.info_frame, 1, "Records", "0")
        self._create_info_card(self.info_frame, 2, "Tree Height", "0")
        self._create_info_card(self.info_frame, 3, "Root Hash", "Not built")
        
        # Output area
        self.output_frame = ctk.CTkFrame(self.main_frame)
        self.output_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.output_frame.grid_columnconfigure(0, weight=1)
        self.output_frame.grid_rowconfigure(0, weight=1)
        
        self.output_text = ctk.CTkTextbox(
            self.output_frame,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word"
        )
        self.output_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Welcome message
        self._log("=" * 60)
        self._log("Welcome to Merkle Tree Integrity Verification System!")
        self._log("=" * 60)
        self._log("\n1. Click 'Load Dataset' to load Amazon review data")
        self._log("2. Click 'Build Tree' to construct the Merkle Tree")
        self._log("3. Use other buttons to verify, generate proofs, etc.")
        self._log("\n" + "=" * 60)
        
    def _create_info_card(self, parent, col: int, title: str, value: str):
        """Create an info card widget."""
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=col, padx=5, pady=5, sticky="nsew")
        
        title_label = ctk.CTkLabel(
            card, text=title, 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="gray"
        )
        title_label.pack(pady=(5, 0))
        
        value_label = ctk.CTkLabel(
            card, text=value,
            font=ctk.CTkFont(size=14)
        )
        value_label.pack(pady=(0, 5))
        
        # Store reference for updates
        setattr(self, f"info_{title.lower().replace(' ', '_')}", value_label)
        
    def _create_status_bar(self):
        """Create the status bar."""
        self.status_bar = ctk.CTkLabel(
            self,
            text="Ready",
            anchor="w",
            font=ctk.CTkFont(size=11)
        )
        self.status_bar.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
    def _log(self, message: str):
        """Log a message to the output area."""
        self.output_text.insert("end", message + "\n")
        self.output_text.see("end")
        
    def _clear_log(self):
        """Clear the output area."""
        self.output_text.delete("1.0", "end")
        
    def _set_status(self, message: str):
        """Set the status bar message."""
        self.status_bar.configure(text=message)
        self.update()
        
    def _update_info(self):
        """Update the info cards."""
        self.info_dataset.configure(text=self.dataset_name or "None")
        self.info_records.configure(text=f"{len(self.reviews):,}")
        
        if self.tree:
            self.info_tree_height.configure(text=str(self.tree.height))
            root = self.tree.get_root_hash()
            self.info_root_hash.configure(text=root[:16] + "..." if root else "Not built")
        else:
            self.info_tree_height.configure(text="0")
            self.info_root_hash.configure(text="Not built")
    
    def _change_appearance(self, mode: str):
        """Change the appearance mode."""
        ctk.set_appearance_mode(mode.lower())
        
    # ==================== Actions ====================
    
    def _action_load(self):
        """Load dataset action."""
        self._clear_log()
        self._log("=== LOAD DATASET ===\n")
        
        # Check for dataset files
        data_dir = "data"
        if not os.path.exists(data_dir):
            messagebox.showerror("Error", "Data directory not found!")
            return
        
        files = [f for f in os.listdir(data_dir) if f.endswith(('.json', '.jsonl'))]
        if not files:
            messagebox.showerror("Error", "No dataset files found in 'data/' directory!")
            return
        
        # Create dialog
        dialog = ctk.CTkInputDialog(
            text=f"Enter record limit (or leave empty for all):\n\nAvailable: {', '.join(files)}",
            title="Load Dataset"
        )
        limit_str = dialog.get_input()
        
        if limit_str is None:
            return
        
        limit = int(limit_str) if limit_str and limit_str.isdigit() else None
        
        def load_task():
            try:
                self._set_status("Loading dataset...")
                self._log(f"Loading {files[0]}...")
                if limit:
                    self._log(f"Limit: {limit:,} records")
                
                self.loader = DataLoader()
                self.reviews = self.loader.load_reviews(
                    files[0], limit=limit, show_progress=False
                )
                self.dataset_name = files[0].replace('.json', '').replace('.jsonl', '')
                
                # Log stats
                stats = self.loader.get_dataset_stats()
                self._log(f"\n✓ Loaded {len(self.reviews):,} reviews")
                self._log(f"  Unique products: {stats['unique_products']:,}")
                self._log(f"  Average rating: {stats['average_rating']:.2f}")
                self._log(f"  Verified purchases: {stats['verified_percentage']:.1f}%")
                
                self._update_info()
                self._set_status(f"Loaded {len(self.reviews):,} reviews")
                
            except Exception as e:
                self._log(f"\n✗ Error: {e}")
                self._set_status("Load failed")
        
        threading.Thread(target=load_task, daemon=True).start()
        
    def _action_build(self):
        """Build Merkle Tree action."""
        if not self.reviews:
            messagebox.showwarning("Warning", "Please load a dataset first!")
            return
        
        self._clear_log()
        self._log("=== BUILD MERKLE TREE ===\n")
        
        def build_task():
            try:
                self._set_status("Building Merkle Tree...")
                self._log(f"Building tree from {len(self.reviews):,} reviews...")
                
                start = time.perf_counter()
                self.tree = MerkleTree()
                root = self.tree.build(self.reviews, show_progress=False)
                elapsed = time.perf_counter() - start
                
                self.detector = TamperDetector(self.tree, self.reviews)
                
                self._log(f"\n✓ Tree built successfully!")
                self._log(f"  Build time: {elapsed:.3f} seconds")
                self._log(f"  Tree height: {self.tree.height}")
                self._log(f"  Total nodes: {self.tree.total_nodes:,}")
                self._log(f"\n  Root Hash:")
                self._log(f"  {root}")
                
                self._update_info()
                self._set_status("Tree built successfully")
                
            except Exception as e:
                self._log(f"\n✗ Error: {e}")
                self._set_status("Build failed")
        
        threading.Thread(target=build_task, daemon=True).start()
        
    def _action_view(self):
        """View dataset action."""
        if not self.reviews:
            messagebox.showwarning("Warning", "Please load a dataset first!")
            return
        
        self._clear_log()
        self._log("=== DATASET VIEWER ===\n")
        self._log(f"{'Review ID':<16} {'ASIN':<12} {'Rating':<8} {'Title':<40}")
        self._log("-" * 80)
        
        for r in self.reviews[:20]:
            title = r.title[:37] + "..." if len(r.title) > 40 else r.title
            self._log(f"{r.review_id:<16} {r.asin:<12} {r.rating:<8} {title:<40}")
        
        if len(self.reviews) > 20:
            self._log(f"\n... and {len(self.reviews) - 20:,} more reviews")
            
    def _action_save(self):
        """Save root action."""
        if not self.tree:
            messagebox.showwarning("Warning", "Please build the Merkle Tree first!")
            return
        
        try:
            self.verifier.save_root(
                root_hash=self.tree.get_root_hash(),
                dataset_name=self.dataset_name,
                record_count=len(self.reviews),
                tree_height=self.tree.height
            )
            self._log("\n✓ Root hash saved successfully!")
            self._set_status("Root saved")
            
        except Exception as e:
            self._log(f"\n✗ Error saving root: {e}")
            
    def _action_verify(self):
        """Verify integrity action."""
        if not self.tree:
            messagebox.showwarning("Warning", "Please build the Merkle Tree first!")
            return
        
        self._clear_log()
        self._log("=== VERIFY DATA INTEGRITY ===\n")
        
        result = self.verifier.verify_integrity(
            self.tree.get_root_hash(),
            self.dataset_name
        )
        
        if result['status'] == "INTEGRITY_VERIFIED":
            self._log("✓ " + result['message'])
            self._log("\n  Data integrity VERIFIED")
        elif result['status'] == "INTEGRITY_VIOLATED":
            self._log("✗ " + result['message'])
            self._log("\n  WARNING: Data may have been tampered with!")
        else:
            self._log("⚠ " + result['message'])
        
        self._log(f"\n  Current Root: {result.get('current_hash', 'N/A')[:32]}...")
        if result.get('stored_hash'):
            self._log(f"  Stored Root:  {result['stored_hash'][:32]}...")
            
    def _action_proof(self):
        """Generate proof action."""
        if not self.tree:
            messagebox.showwarning("Warning", "Please build the Merkle Tree first!")
            return
        
        # Get review ID
        sample = self.reviews[:5]
        sample_ids = ", ".join([r.review_id[:10] for r in sample])
        
        dialog = ctk.CTkInputDialog(
            text=f"Enter Review ID:\n\nSamples: {sample_ids}...",
            title="Generate Existence Proof"
        )
        review_id = dialog.get_input()
        
        if not review_id:
            return
        
        self._clear_log()
        self._log("=== EXISTENCE PROOF ===\n")
        self._log(f"Searching for: {review_id}\n")
        
        start = time.perf_counter()
        proof = self.tree.generate_proof(review_id)
        gen_time = (time.perf_counter() - start) * 1000
        
        if proof is None:
            self._log(f"✗ Review {review_id} NOT FOUND in dataset")
            return
        
        self._log(f"✓ Review {review_id} EXISTS\n")
        self._log(f"  Proof Length: {len(proof)} hashes")
        self._log(f"  Generation Time: {gen_time:.4f} ms")
        
        # Verify
        review = self.loader.get_review_by_id(review_id)
        if review:
            is_valid = self.tree.verify_proof(
                review_id, review.raw_hash, proof, self.tree.get_root_hash()
            )
            self._log(f"\n  Proof Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
        
        # Show proof path
        self._log("\n" + self.tree.visualize_proof_path(proof, review.raw_hash))
        
    def _action_tamper(self):
        """Simulate tampering action."""
        if not self.tree or not self.detector:
            messagebox.showwarning("Warning", "Please build the Merkle Tree first!")
            return
        
        self._clear_log()
        self._log("=== TAMPERING SIMULATION ===\n")
        
        # Random tampering
        choice = random.choice(["modify", "delete", "insert"])
        
        if choice == "modify":
            idx = random.randint(0, len(self.reviews) - 1)
            tampered, desc = TamperSimulator.modify_record(self.reviews, index=idx)
        elif choice == "delete":
            idx = random.randint(0, len(self.reviews) - 1)
            tampered, desc = TamperSimulator.delete_record(self.reviews, index=idx)
        else:
            tampered, desc = TamperSimulator.insert_record(self.reviews)
        
        self._log(f"Action: {desc}\n")
        self._log("Detecting tampering...\n")
        
        result = self.detector.detect_tampering(tampered, show_progress=False)
        
        if result.detected:
            self._log("⚠️ TAMPERING DETECTED!")
            self._log(f"\n  Type: {result.tamper_type.value}")
            self._log(f"  Message: {result.message}")
            self._log(f"\n  Original Root: {result.original_root[:32]}...")
            self._log(f"  Current Root:  {result.current_root[:32]}...")
        else:
            self._log("✓ No tampering detected")
            
    def _action_benchmark(self):
        """Run performance benchmark."""
        if not self.reviews:
            messagebox.showwarning("Warning", "Please load a dataset first!")
            return
        
        self._clear_log()
        self._log("=== PERFORMANCE BENCHMARK ===\n")
        
        def benchmark_task():
            try:
                self._set_status("Running benchmark...")
                
                # Hash performance
                self._log("1. Measuring hash performance...")
                hash_metrics = self.monitor.measure_hash_performance(self.reviews)
                self._log(f"   Avg hash time: {hash_metrics['avg_ms']:.4f} ms")
                
                # Build tree
                self._log("\n2. Building Merkle Tree...")
                tree = MerkleTree()
                start = time.perf_counter()
                tree.build(self.reviews, show_progress=False)
                build_time = time.perf_counter() - start
                self._log(f"   Build time: {build_time:.3f} seconds")
                
                # Proof performance
                self._log("\n3. Measuring proof performance (100 samples)...")
                proof_metrics = self.monitor.measure_proof_performance(tree, self.reviews)
                self._log(f"   Avg proof generation: {proof_metrics['generation_avg_ms']:.4f} ms")
                self._log(f"   Avg proof verification: {proof_metrics['verification_avg_ms']:.4f} ms")
                
                total = proof_metrics['generation_avg_ms'] + proof_metrics['verification_avg_ms']
                self._log(f"\n   Total proof time: {total:.4f} ms")
                if total < 100:
                    self._log("   ✓ Meets <100ms requirement!")
                else:
                    self._log("   ✗ Exceeds 100ms requirement")
                
                self._set_status("Benchmark complete")
                
            except Exception as e:
                self._log(f"\n✗ Error: {e}")
                self._set_status("Benchmark failed")
        
        threading.Thread(target=benchmark_task, daemon=True).start()


def run_gui():
    """Launch the GUI application."""
    app = MerkleTreeGUI()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
