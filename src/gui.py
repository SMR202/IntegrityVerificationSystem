"""
Modern Merkle Tree GUI with Visual Tree, Animated Proofs, and Interactive Dashboard
Uses CustomTkinter for modern dark theme
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox, Canvas
import threading
import time
import json
import os
from datetime import datetime
from typing import Optional, List, Tuple
import math

# Import our modules
from src.data_loader import DataLoader, Review
from src.merkle_tree import MerkleTree, MerkleNode
from src.integrity import IntegrityVerifier
from src.tamper_detection import TamperDetector, TamperSimulator, TamperType
from src.performance import PerformanceMonitor

# Set appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class AnimatedCanvas(Canvas):
    """Custom canvas for tree visualization with animations"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(bg='#1a1a2e', highlightthickness=0)
        self.nodes = {}  # Store node positions {node_id: {x, y, oval, text, hash}}
        self.edges = {}  # Store edge references {edge_id: line_item}
        self.node_by_hash = {}  # Map hash prefix to node_id
        self.highlighted_path = []
        self.animation_running = False
        self.animation_speed = 0.5  # seconds per step
        
    def clear(self):
        self.delete("all")
        self.nodes = {}
        self.edges = {}
        self.node_by_hash = {}
        self.highlighted_path = []
        
    def draw_node(self, x: int, y: int, text: str, node_id: str, 
                  color: str = "#4a9eff", is_leaf: bool = False):
        """Draw a single node"""
        radius = 25 if is_leaf else 30
        
        # Node circle
        oval = self.create_oval(
            x - radius, y - radius, 
            x + radius, y + radius,
            fill=color, outline="#ffffff", width=2,
            tags=(node_id, "node")
        )
        
        # Node text (first 6 chars of hash)
        display_text = text[:6] + "..." if len(text) > 6 else text
        text_item = self.create_text(
            x, y, text=display_text, 
            fill="white", font=("Consolas", 8, "bold"),
            tags=(node_id, "text")
        )
        
        self.nodes[node_id] = {
            'x': x, 'y': y, 'oval': oval, 
            'text': text_item, 'hash': text,
            'radius': radius, 'is_leaf': is_leaf,
            'original_color': color
        }
        
        # Map hash prefix for quick lookup
        self.node_by_hash[text[:16]] = node_id
        
        return oval
    
    def draw_edge(self, x1: int, y1: int, x2: int, y2: int, 
                  edge_id: str, color: str = "#555555"):
        """Draw edge between nodes"""
        line = self.create_line(
            x1, y1, x2, y2,
            fill=color, width=2, tags=(edge_id, "edge")
        )
        self.edges[edge_id] = {'line': line, 'coords': (x1, y1, x2, y2), 'original_color': color}
        self.tag_lower(line)
        return line
    
    def highlight_path(self, node_ids: List[str], callback=None):
        """Animate highlighting a path through the tree"""
        self.animation_running = True
        
        def animate():
            colors = ["#ff6b6b", "#feca57", "#48dbfb", "#1dd1a1"]
            for i, node_id in enumerate(node_ids):
                if not self.animation_running:
                    break
                if node_id in self.nodes:
                    color = colors[i % len(colors)]
                    self.itemconfig(self.nodes[node_id]['oval'], fill=color)
                    self.update()
                    time.sleep(self.animation_speed)
            
            self.animation_running = False
            if callback:
                callback()
        
        threading.Thread(target=animate, daemon=True).start()
    
    def animate_proof_verification(self, leaf_hash: str, proof: List[Tuple[str, str]], 
                                    root_hash: str, status_callback=None, complete_callback=None):
        """
        Animate the proof verification path from leaf to root.
        Shows hash computation at each step with visual effects.
        """
        self.animation_running = True
        self.reset_colors()
        
        def animate():
            import hashlib
            
            # Colors for animation stages
            LEAF_COLOR = "#ff6b6b"      # Red - starting point
            SIBLING_COLOR = "#feca57"   # Yellow - sibling node
            COMPUTING_COLOR = "#48dbfb"  # Blue - computing
            VERIFIED_COLOR = "#1dd1a1"   # Green - verified
            PATH_COLOR = "#ff6b6b"       # Red - path edge
            
            current_hash = leaf_hash
            
            # Highlight leaf node
            if status_callback:
                status_callback(f"Step 0: Starting at leaf\n  Hash: {current_hash[:32]}...")
            
            # Find and highlight leaf
            leaf_node_id = self.node_by_hash.get(current_hash[:16])
            if leaf_node_id and leaf_node_id in self.nodes:
                self._pulse_node(leaf_node_id, LEAF_COLOR, 3)
            
            time.sleep(self.animation_speed)
            
            # Process each proof step
            for i, (sibling_hash, direction) in enumerate(proof):
                if not self.animation_running:
                    break
                
                # Update status
                dir_name = "LEFT" if direction == "L" else "RIGHT"
                arrow = "←" if direction == "L" else "→"
                
                if status_callback:
                    status_callback(
                        f"Step {i+1}: Combine with {dir_name} sibling\n"
                        f"  Sibling: {sibling_hash[:32]}...\n"
                        f"  Direction: {arrow}"
                    )
                
                # Highlight sibling node
                sibling_node_id = self.node_by_hash.get(sibling_hash[:16])
                if sibling_node_id and sibling_node_id in self.nodes:
                    self._pulse_node(sibling_node_id, SIBLING_COLOR, 2)
                
                time.sleep(self.animation_speed * 0.5)
                
                # Compute new hash with animation
                if direction == "L":
                    combined = sibling_hash + current_hash
                else:
                    combined = current_hash + sibling_hash
                
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                
                # Show computing animation
                if status_callback:
                    status_callback(
                        f"Step {i+1}: Computing parent hash...\n"
                        f"  Input: H({direction == 'L' and 'sibling + current' or 'current + sibling'})\n"
                        f"  Result: {new_hash[:32]}..."
                    )
                
                # Find and highlight parent node
                parent_node_id = self.node_by_hash.get(new_hash[:16])
                if parent_node_id and parent_node_id in self.nodes:
                    self._pulse_node(parent_node_id, COMPUTING_COLOR, 2)
                    time.sleep(self.animation_speed * 0.3)
                    self.itemconfig(self.nodes[parent_node_id]['oval'], fill=VERIFIED_COLOR)
                
                current_hash = new_hash
                time.sleep(self.animation_speed * 0.5)
            
            # Final verification
            verified = current_hash == root_hash
            
            if status_callback:
                if verified:
                    status_callback(
                        f"✅ VERIFICATION SUCCESSFUL!\n\n"
                        f"  Computed Root: {current_hash[:32]}...\n"
                        f"  Expected Root: {root_hash[:32]}...\n\n"
                        f"  ✓ Hashes match - proof is valid!"
                    )
                else:
                    status_callback(
                        f"❌ VERIFICATION FAILED!\n\n"
                        f"  Computed Root: {current_hash[:32]}...\n"
                        f"  Expected Root: {root_hash[:32]}...\n\n"
                        f"  ✗ Hashes do not match!"
                    )
            
            # Highlight root node
            root_node_id = self.node_by_hash.get(root_hash[:16])
            if root_node_id and root_node_id in self.nodes:
                final_color = VERIFIED_COLOR if verified else "#e74c3c"
                self._pulse_node(root_node_id, final_color, 4)
            
            self.animation_running = False
            
            if complete_callback:
                complete_callback(verified)
        
        threading.Thread(target=animate, daemon=True).start()
    
    def _pulse_node(self, node_id: str, target_color: str, pulses: int = 2):
        """Create a pulsing effect on a node"""
        if node_id not in self.nodes:
            return
            
        node = self.nodes[node_id]
        original_color = node.get('original_color', '#4a9eff')
        
        for _ in range(pulses):
            if not self.animation_running:
                break
            self.itemconfig(node['oval'], fill=target_color, outline="#ffffff", width=4)
            self.update()
            time.sleep(0.1)
            self.itemconfig(node['oval'], fill=original_color, outline="#ffffff", width=2)
            self.update()
            time.sleep(0.1)
        
        # Leave highlighted
        self.itemconfig(node['oval'], fill=target_color, outline="#ffffff", width=3)
        self.update()
    
    def draw_animated_arrow(self, x1: int, y1: int, x2: int, y2: int, color: str = "#ff6b6b"):
        """Draw an animated arrow between two points"""
        # Create arrow with animation
        arrow = self.create_line(
            x1, y1, x2, y2,
            fill=color, width=4, arrow="last", arrowshape=(12, 15, 5),
            tags=("animated_arrow",)
        )
        return arrow
    
    def clear_animated_elements(self):
        """Remove temporary animated elements"""
        self.delete("animated_arrow")
        self.delete("hash_display")
    
    def reset_colors(self):
        """Reset all node colors to original"""
        self.animation_running = False
        self.clear_animated_elements()
        for node_id, node_data in self.nodes.items():
            original = node_data.get('original_color', '#4a9eff')
            self.itemconfig(node_data['oval'], fill=original, outline="#ffffff", width=2)
        for edge_id, edge_data in self.edges.items():
            original = edge_data.get('original_color', '#555555')
            self.itemconfig(edge_data['line'], fill=original, width=2)
    
    def set_animation_speed(self, speed: float):
        """Set animation speed (seconds per step)"""
        self.animation_speed = max(0.1, min(2.0, speed))


class ProgressWindow(ctk.CTkToplevel):
    """Progress window for long operations"""
    
    def __init__(self, master, title: str = "Processing..."):
        super().__init__(master)
        self.title(title)
        self.geometry("400x150")
        self.resizable(False, False)
        
        # Center on parent
        self.transient(master)
        self.grab_set()
        
        # Progress elements
        self.label = ctk.CTkLabel(self, text="Initializing...", font=("Segoe UI", 14))
        self.label.pack(pady=20)
        
        self.progress = ctk.CTkProgressBar(self, width=350)
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        self.detail_label = ctk.CTkLabel(self, text="", font=("Segoe UI", 11))
        self.detail_label.pack(pady=5)
        
        self.cancelled = False
        
    def update_progress(self, value: float, text: str = "", detail: str = ""):
        """Update progress bar and labels"""
        self.progress.set(value)
        if text:
            self.label.configure(text=text)
        if detail:
            self.detail_label.configure(text=detail)
        self.update()


class TreeVisualizer(ctk.CTkFrame):
    """Visual tree representation panel"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Controls frame
        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(controls, text="🌳 Tree Visualization", 
                     font=("Segoe UI", 16, "bold")).pack(side="left", padx=10)
        
        self.depth_var = ctk.StringVar(value="4")
        ctk.CTkLabel(controls, text="Display Depth:").pack(side="left", padx=5)
        self.depth_spinner = ctk.CTkOptionMenu(
            controls, values=["2", "3", "4", "5", "6"],
            variable=self.depth_var, width=70
        )
        self.depth_spinner.pack(side="left", padx=5)
        
        self.redraw_btn = ctk.CTkButton(
            controls, text="↻ Redraw", width=80,
            command=self.redraw_tree
        )
        self.redraw_btn.pack(side="left", padx=5)
        
        self.zoom_scale = ctk.CTkSlider(
            controls, from_=0.5, to=2.0, 
            number_of_steps=15, width=100
        )
        self.zoom_scale.set(1.0)
        self.zoom_scale.pack(side="right", padx=10)
        ctk.CTkLabel(controls, text="Zoom:").pack(side="right")
        
        # Canvas with scrollbars
        canvas_frame = ctk.CTkFrame(self)
        canvas_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.canvas = AnimatedCanvas(canvas_frame, width=800, height=500)
        self.canvas.pack(fill="both", expand=True)
        
        # Tree reference
        self.tree: Optional[MerkleTree] = None
        
        # Info panel
        self.info_label = ctk.CTkLabel(
            self, text="Load data and build tree to visualize",
            font=("Segoe UI", 11)
        )
        self.info_label.pack(pady=5)
        
    def set_tree(self, tree: MerkleTree):
        """Set the tree to visualize"""
        self.tree = tree
        self.redraw_tree()
        
    def redraw_tree(self):
        """Redraw the tree visualization"""
        if not self.tree or not self.tree.root:
            self.canvas.clear()
            self.canvas.create_text(
                400, 250, text="No tree to display",
                fill="#888888", font=("Segoe UI", 16)
            )
            return
            
        self.canvas.clear()
        max_depth = int(self.depth_var.get())
        zoom = self.zoom_scale.get()
        
        canvas_width = self.canvas.winfo_width() or 800
        canvas_height = self.canvas.winfo_height() or 500
        
        self._draw_node_recursive(
            self.tree.root, 
            canvas_width // 2, 
            50 * zoom,
            canvas_width // 4,
            0, 
            max_depth,
            zoom
        )
        
        total_leaves = len(self.tree.leaves) if self.tree.leaves else 0
        tree_depth = self._calculate_depth(self.tree.root)
        self.info_label.configure(
            text=f"Tree Depth: {tree_depth} | Total Leaves: {total_leaves:,} | "
                 f"Root: {self.tree.root.hash[:16]}..."
        )
    
    def _draw_node_recursive(self, node: MerkleNode, x: int, y: int, 
                             x_offset: int, depth: int, max_depth: int, zoom: float):
        """Recursively draw tree nodes"""
        if not node or depth > max_depth:
            return
            
        node_id = f"node_{id(node)}"
        is_leaf = node.left is None and node.right is None
        
        # Color based on depth
        colors = ["#ff6b6b", "#feca57", "#48dbfb", "#1dd1a1", "#a55eea", "#fd79a8"]
        color = colors[depth % len(colors)]
        
        # Draw children first (so edges are behind nodes)
        y_step = int(80 * zoom)
        new_x_offset = max(int(x_offset * 0.5), 30)
        
        if node.left and depth < max_depth:
            child_x = x - new_x_offset
            child_y = y + y_step
            edge_id = f"edge_{id(node)}_{id(node.left)}"
            self.canvas.draw_edge(x, y + 25, child_x, child_y - 25, edge_id)
            self._draw_node_recursive(
                node.left, child_x, child_y, 
                new_x_offset, depth + 1, max_depth, zoom
            )
            
        if node.right and depth < max_depth:
            child_x = x + new_x_offset
            child_y = y + y_step
            edge_id = f"edge_{id(node)}_{id(node.right)}"
            self.canvas.draw_edge(x, y + 25, child_x, child_y - 25, edge_id)
            self._draw_node_recursive(
                node.right, child_x, child_y, 
                new_x_offset, depth + 1, max_depth, zoom
            )
        
        # Draw this node
        self.canvas.draw_node(int(x), int(y), node.hash, node_id, color, is_leaf)
        
        # Show "..." if truncated
        if (node.left or node.right) and depth == max_depth:
            self.canvas.create_text(
                x, y + 50, text="...", 
                fill="#888888", font=("Segoe UI", 14, "bold")
            )
    
    def _calculate_depth(self, node: MerkleNode) -> int:
        """Calculate tree depth"""
        if not node:
            return 0
        if not node.left and not node.right:
            return 1
        return 1 + max(
            self._calculate_depth(node.left),
            self._calculate_depth(node.right)
        )
    
    def animate_proof_path(self, proof: List[Tuple[str, str]], leaf_hash: str = None, 
                           root_hash: str = None, callback=None):
        """
        Animate a proof path through the tree visualization.
        Highlights the verification path from leaf to root.
        """
        if not self.tree or not self.tree.root:
            return
        
        # Reset colors first
        self.canvas.reset_colors()
        
        if leaf_hash and root_hash:
            # Use the advanced animation
            self.canvas.animate_proof_verification(
                leaf_hash, proof, root_hash,
                status_callback=None,
                complete_callback=callback
            )
        else:
            # Simple path highlight
            node_id = f"node_{id(self.tree.root)}"
            self.canvas.highlight_path([node_id], callback)
    
    def reset_animation(self):
        """Reset animation state"""
        self.canvas.reset_colors()


class DashboardPanel(ctk.CTkFrame):
    """Main dashboard with status indicators"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Title
        title = ctk.CTkLabel(
            self, text="📊 Merkle Tree Dashboard",
            font=("Segoe UI", 24, "bold")
        )
        title.pack(pady=20)
        
        # Stats cards container
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20, pady=10)
        
        # Create stat cards
        self.cards = {}
        card_configs = [
            ("data", "📁 Data Status", "No data loaded", "#3498db"),
            ("tree", "🌳 Tree Status", "No tree built", "#2ecc71"),
            ("integrity", "🔒 Integrity", "Not verified", "#9b59b6"),
            ("performance", "⚡ Performance", "No metrics", "#e74c3c"),
        ]
        
        for i, (key, title, default, color) in enumerate(card_configs):
            card = self._create_stat_card(cards_frame, title, default, color)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            self.cards[key] = card
            cards_frame.columnconfigure(i, weight=1)
        
        # Quick actions
        actions_frame = ctk.CTkFrame(self)
        actions_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            actions_frame, text="⚡ Quick Actions",
            font=("Segoe UI", 16, "bold")
        ).pack(anchor="w", padx=10, pady=10)
        
        buttons_frame = ctk.CTkFrame(actions_frame, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=10, pady=10)
        
        self.quick_buttons = {}
        button_configs = [
            ("load", "📂 Load Data", "#3498db"),
            ("build", "🏗️ Build Tree", "#2ecc71"),
            ("verify", "✅ Verify", "#9b59b6"),
            ("benchmark", "📊 Benchmark", "#e74c3c"),
        ]
        
        for i, (key, text, color) in enumerate(button_configs):
            btn = ctk.CTkButton(
                buttons_frame, text=text, 
                fg_color=color, hover_color=self._darken(color),
                height=50, font=("Segoe UI", 14, "bold")
            )
            btn.grid(row=0, column=i, padx=10, pady=5, sticky="ew")
            self.quick_buttons[key] = btn
            buttons_frame.columnconfigure(i, weight=1)
        
        # Recent activity log
        log_frame = ctk.CTkFrame(self)
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(
            log_frame, text="📝 Activity Log",
            font=("Segoe UI", 16, "bold")
        ).pack(anchor="w", padx=10, pady=10)
        
        self.log_text = ctk.CTkTextbox(log_frame, height=200, font=("Consolas", 11))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _create_stat_card(self, parent, title: str, value: str, color: str):
        """Create a statistics card"""
        card = ctk.CTkFrame(parent, fg_color="#2d2d44", corner_radius=15)
        
        ctk.CTkLabel(
            card, text=title,
            font=("Segoe UI", 12), text_color="#aaaaaa"
        ).pack(pady=(15, 5))
        
        value_label = ctk.CTkLabel(
            card, text=value,
            font=("Segoe UI", 14, "bold"), text_color=color
        )
        value_label.pack(pady=(5, 15))
        card.value_label = value_label
        card.color = color
        
        return card
    
    def update_card(self, key: str, value: str, color: str = None):
        """Update a stat card value"""
        if key in self.cards:
            card = self.cards[key]
            card.value_label.configure(text=value)
            if color:
                card.value_label.configure(text_color=color)
    
    def log(self, message: str):
        """Add message to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
    
    def _darken(self, hex_color: str) -> str:
        """Darken a hex color"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        darker = tuple(max(0, int(c * 0.8)) for c in rgb)
        return f"#{darker[0]:02x}{darker[1]:02x}{darker[2]:02x}"


class IntegrityPanel(ctk.CTkFrame):
    """Integrity verification panel"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Title
        ctk.CTkLabel(
            self, text="🔒 Integrity Verification",
            font=("Segoe UI", 20, "bold")
        ).pack(pady=20)
        
        # Current root display
        root_frame = ctk.CTkFrame(self)
        root_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(
            root_frame, text="Current Merkle Root:",
            font=("Segoe UI", 12)
        ).pack(anchor="w", padx=10, pady=5)
        
        self.root_label = ctk.CTkLabel(
            root_frame, text="No tree built",
            font=("Consolas", 11), text_color="#4a9eff"
        )
        self.root_label.pack(anchor="w", padx=10, pady=5)
        
        # Saved roots list
        saved_frame = ctk.CTkFrame(self)
        saved_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(
            saved_frame, text="📋 Saved Root Records:",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=10, pady=10)
        
        self.roots_list = ctk.CTkTextbox(saved_frame, height=200, font=("Consolas", 10))
        self.roots_list.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Action buttons
        buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=20, pady=10)
        
        self.save_btn = ctk.CTkButton(
            buttons_frame, text="💾 Save Current Root",
            fg_color="#2ecc71", hover_color="#27ae60",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.save_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        self.verify_btn = ctk.CTkButton(
            buttons_frame, text="✅ Verify Integrity",
            fg_color="#3498db", hover_color="#2980b9",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.verify_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        self.compare_btn = ctk.CTkButton(
            buttons_frame, text="🔍 Compare Roots",
            fg_color="#9b59b6", hover_color="#8e44ad",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.compare_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        # Result display
        self.result_frame = ctk.CTkFrame(self)
        self.result_frame.pack(fill="x", padx=20, pady=10)
        
        self.result_label = ctk.CTkLabel(
            self.result_frame, text="",
            font=("Segoe UI", 14, "bold")
        )
        self.result_label.pack(pady=15)
    
    def set_root(self, root_hash: str):
        """Update displayed root hash"""
        self.root_label.configure(text=root_hash)
    
    def update_saved_roots(self, roots: list):
        """Update the saved roots display"""
        self.roots_list.delete("1.0", "end")
        for i, record in enumerate(roots, 1):
            self.roots_list.insert(
                "end",
                f"{i}. [{record.get('timestamp', 'N/A')}]\n"
                f"   Dataset: {record.get('dataset', 'Unknown')}\n"
                f"   Records: {record.get('record_count', 0):,}\n"
                f"   Root: {record.get('root_hash', 'N/A')[:32]}...\n\n"
            )
    
    def show_result(self, success: bool, message: str):
        """Show verification result"""
        if success:
            self.result_label.configure(
                text=f"✅ {message}",
                text_color="#2ecc71"
            )
        else:
            self.result_label.configure(
                text=f"❌ {message}",
                text_color="#e74c3c"
            )


class ProofPanel(ctk.CTkFrame):
    """Proof generation and verification panel with animated visualization"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Title
        ctk.CTkLabel(
            self, text="🔐 Proof Generation & Animated Verification",
            font=("Segoe UI", 20, "bold")
        ).pack(pady=15)
        
        # Main container - two columns
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=5)
        main_container.columnconfigure(0, weight=1)
        main_container.columnconfigure(1, weight=1)
        
        # Left column - Input and proof display
        left_frame = ctk.CTkFrame(main_container)
        left_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Search mode selection
        search_mode_frame = ctk.CTkFrame(left_frame)
        search_mode_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            search_mode_frame, text="🔍 Search Mode:",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        # Search mode buttons (segmented control)
        mode_buttons_frame = ctk.CTkFrame(search_mode_frame, fg_color="transparent")
        mode_buttons_frame.pack(fill="x", padx=10, pady=5)
        
        self.search_mode_var = ctk.StringVar(value="index")
        
        self.mode_index_btn = ctk.CTkButton(
            mode_buttons_frame, text="📍 Index",
            fg_color="#3498db", hover_color="#2980b9",
            height=32, width=100, font=("Segoe UI", 11),
            command=lambda: self._set_search_mode("index")
        )
        self.mode_index_btn.pack(side="left", padx=2)
        
        self.mode_review_btn = ctk.CTkButton(
            mode_buttons_frame, text="🆔 Review ID",
            fg_color="#555555", hover_color="#666666",
            height=32, width=100, font=("Segoe UI", 11),
            command=lambda: self._set_search_mode("review_id")
        )
        self.mode_review_btn.pack(side="left", padx=2)
        
        self.mode_product_btn = ctk.CTkButton(
            mode_buttons_frame, text="📦 Product ID",
            fg_color="#555555", hover_color="#666666",
            height=32, width=100, font=("Segoe UI", 11),
            command=lambda: self._set_search_mode("product_id")
        )
        self.mode_product_btn.pack(side="left", padx=2)
        
        # Input section - changes based on mode
        input_frame = ctk.CTkFrame(left_frame)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        # Index input (default visible)
        self.index_input_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        self.index_input_frame.pack(fill="x")
        
        ctk.CTkLabel(
            self.index_input_frame, text="Enter Review Index (0-based):",
            font=("Segoe UI", 11)
        ).pack(anchor="w", padx=10, pady=2)
        
        self.index_entry = ctk.CTkEntry(
            self.index_input_frame, placeholder_text="e.g., 0, 100, 1000...",
            height=35, font=("Segoe UI", 11)
        )
        self.index_entry.pack(fill="x", padx=10, pady=5)
        
        # Review ID input (hidden initially)
        self.review_id_input_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        
        ctk.CTkLabel(
            self.review_id_input_frame, text="Enter Review ID:",
            font=("Segoe UI", 11)
        ).pack(anchor="w", padx=10, pady=2)
        
        self.review_id_entry = ctk.CTkEntry(
            self.review_id_input_frame, placeholder_text="e.g., R3FTHZL6BOP5PE...",
            height=35, font=("Segoe UI", 11)
        )
        self.review_id_entry.pack(fill="x", padx=10, pady=5)
        
        # Product ID input (hidden initially)
        self.product_id_input_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        
        ctk.CTkLabel(
            self.product_id_input_frame, text="Enter Product ID (ASIN):",
            font=("Segoe UI", 11)
        ).pack(anchor="w", padx=10, pady=2)
        
        self.product_id_entry = ctk.CTkEntry(
            self.product_id_input_frame, placeholder_text="e.g., B00000JBAT...",
            height=35, font=("Segoe UI", 11)
        )
        self.product_id_entry.pack(fill="x", padx=10, pady=5)
        
        # Search button for product ID
        self.search_product_btn = ctk.CTkButton(
            self.product_id_input_frame, text="🔎 Search Product",
            fg_color="#9b59b6", hover_color="#8e44ad",
            height=32, font=("Segoe UI", 11)
        )
        self.search_product_btn.pack(fill="x", padx=10, pady=5)
        
        # Product reviews list (for product ID search)
        self.product_reviews_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        
        ctk.CTkLabel(
            self.product_reviews_frame, text="Select a review:",
            font=("Segoe UI", 11)
        ).pack(anchor="w", padx=10, pady=2)
        
        self.product_reviews_list = ctk.CTkTextbox(
            self.product_reviews_frame, height=80, font=("Consolas", 9)
        )
        self.product_reviews_list.pack(fill="x", padx=10, pady=2)
        
        select_frame = ctk.CTkFrame(self.product_reviews_frame, fg_color="transparent")
        select_frame.pack(fill="x", padx=10, pady=2)
        
        ctk.CTkLabel(select_frame, text="Review #:", font=("Segoe UI", 10)).pack(side="left")
        self.product_review_select = ctk.CTkEntry(
            select_frame, placeholder_text="1", width=60, height=28
        )
        self.product_review_select.pack(side="left", padx=5)
        
        # Action buttons
        buttons_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=10, pady=10)
        
        self.generate_btn = ctk.CTkButton(
            buttons_frame, text="🔑 Generate Proof",
            fg_color="#3498db", hover_color="#2980b9",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.generate_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        self.verify_btn = ctk.CTkButton(
            buttons_frame, text="✅ Verify Proof",
            fg_color="#2ecc71", hover_color="#27ae60",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.verify_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        # Proof display
        proof_frame = ctk.CTkFrame(left_frame)
        proof_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(
            proof_frame, text="📜 Proof Path:",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.proof_text = ctk.CTkTextbox(proof_frame, height=150, font=("Consolas", 10))
        self.proof_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Right column - Animation visualization
        right_frame = ctk.CTkFrame(main_container)
        right_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        
        # Animation header with controls
        anim_header = ctk.CTkFrame(right_frame, fg_color="transparent")
        anim_header.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            anim_header, text="🎬 Proof Verification Animation",
            font=("Segoe UI", 14, "bold")
        ).pack(side="left", padx=5)
        
        # Animation speed control
        speed_frame = ctk.CTkFrame(anim_header, fg_color="transparent")
        speed_frame.pack(side="right", padx=5)
        
        ctk.CTkLabel(speed_frame, text="Speed:", font=("Segoe UI", 10)).pack(side="left", padx=2)
        self.speed_var = ctk.StringVar(value="Normal")
        self.speed_menu = ctk.CTkOptionMenu(
            speed_frame, 
            values=["Slow", "Normal", "Fast"],
            variable=self.speed_var,
            width=80,
            command=self._on_speed_change
        )
        self.speed_menu.pack(side="left", padx=2)
        
        # Animation canvas
        self.anim_canvas_frame = ctk.CTkFrame(right_frame)
        self.anim_canvas_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.anim_canvas = Canvas(
            self.anim_canvas_frame, 
            bg='#1a1a2e', 
            highlightthickness=0,
            height=180
        )
        self.anim_canvas.pack(fill="both", expand=True)
        
        # Animation status display
        status_frame = ctk.CTkFrame(right_frame)
        status_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(
            status_frame, text="📊 Verification Steps:",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.anim_status = ctk.CTkTextbox(status_frame, height=120, font=("Consolas", 9))
        self.anim_status.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Animation control buttons
        anim_controls = ctk.CTkFrame(right_frame, fg_color="transparent")
        anim_controls.pack(fill="x", padx=10, pady=10)
        
        self.animate_btn = ctk.CTkButton(
            anim_controls, text="▶️ Animate Verification",
            fg_color="#9b59b6", hover_color="#8e44ad",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.animate_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        self.stop_btn = ctk.CTkButton(
            anim_controls, text="⏹️ Stop",
            fg_color="#e74c3c", hover_color="#c0392b",
            height=40, font=("Segoe UI", 12, "bold"),
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5, expand=True, fill="x")
        
        # Result
        self.result_label = ctk.CTkLabel(
            self, text="",
            font=("Segoe UI", 14, "bold")
        )
        self.result_label.pack(pady=10)
        
        # Store current proof
        self.current_proof = None
        self.current_leaf_hash = None
        self.current_root_hash = None
        self.animation_running = False
        
        # Animation state
        self._animation_thread = None
        self._animation_speed = 0.5  # seconds per step
        
        # Product search state
        self.product_reviews_cache = []  # Store found product reviews
        
    def _set_search_mode(self, mode: str):
        """Switch between search modes (index, review_id, product_id)"""
        self.search_mode_var.set(mode)
        
        # Update button colors
        active_color = "#3498db"
        inactive_color = "#555555"
        
        self.mode_index_btn.configure(fg_color=active_color if mode == "index" else inactive_color)
        self.mode_review_btn.configure(fg_color=active_color if mode == "review_id" else inactive_color)
        self.mode_product_btn.configure(fg_color=active_color if mode == "product_id" else inactive_color)
        
        # Hide all input frames
        self.index_input_frame.pack_forget()
        self.review_id_input_frame.pack_forget()
        self.product_id_input_frame.pack_forget()
        self.product_reviews_frame.pack_forget()
        
        # Show appropriate input frame and sample data
        if mode == "index":
            self.index_input_frame.pack(fill="x")
        elif mode == "review_id":
            self.review_id_input_frame.pack(fill="x")
            self.show_sample_review_ids()
        elif mode == "product_id":
            self.product_id_input_frame.pack(fill="x")
            self.show_sample_product_ids()
    
    def set_sample_data(self, reviews: list):
        """Store sample data for showing examples to user"""
        self.sample_reviews = reviews[:20] if reviews else []  # Keep first 20 for samples
        
        # Extract unique product IDs
        seen_products = set()
        self.sample_products = []
        for r in reviews[:500]:  # Check first 500 for product diversity
            asin = getattr(r, 'asin', None)
            if asin and asin not in seen_products:
                seen_products.add(asin)
                self.sample_products.append(asin)
                if len(self.sample_products) >= 10:
                    break
        
        # Update sample displays
        self._update_sample_hints()
    
    def _update_sample_hints(self):
        """Update the sample hints in input fields"""
        if hasattr(self, 'sample_reviews') and self.sample_reviews:
            # Update Review ID placeholder with sample
            sample_id = self.sample_reviews[0].review_id
            self.review_id_entry.configure(placeholder_text=f"e.g., {sample_id[:20]}...")
        
        if hasattr(self, 'sample_products') and self.sample_products:
            # Update Product ID placeholder with sample
            self.product_id_entry.configure(placeholder_text=f"e.g., {self.sample_products[0]}")
    
    def get_search_mode(self) -> str:
        """Get current search mode"""
        return self.search_mode_var.get()
    
    def show_sample_review_ids(self):
        """Display sample Review IDs in the proof text area"""
        if not hasattr(self, 'sample_reviews') or not self.sample_reviews:
            self.proof_text.delete("1.0", "end")
            self.proof_text.insert("end", "📋 Load data first to see sample Review IDs")
            return
        
        self.proof_text.delete("1.0", "end")
        self.proof_text.insert("end", "📋 Sample Review IDs (click to copy):\n")
        self.proof_text.insert("end", "-" * 50 + "\n\n")
        
        for i, review in enumerate(self.sample_reviews[:10], 1):
            rating = getattr(review, 'rating', 'N/A')
            title = getattr(review, 'title', '')[:30]
            self.proof_text.insert(
                "end",
                f"{i}. {review.review_id}\n"
                f"   [{rating}★] {title}...\n\n"
            )
    
    def show_sample_product_ids(self):
        """Display sample Product IDs in the proof text area"""
        if not hasattr(self, 'sample_products') or not self.sample_products:
            self.proof_text.delete("1.0", "end")
            self.proof_text.insert("end", "📋 Load data first to see sample Product IDs")
            return
        
        self.proof_text.delete("1.0", "end")
        self.proof_text.insert("end", "📋 Sample Product IDs (ASIN):\n")
        self.proof_text.insert("end", "-" * 50 + "\n\n")
        
        for i, asin in enumerate(self.sample_products[:10], 1):
            self.proof_text.insert("end", f"{i}. {asin}\n")
        
        self.proof_text.insert("end", "\n💡 Enter a Product ID above and click\n")
        self.proof_text.insert("end", "   'Search Product' to find reviews.")
    
    def show_product_reviews(self, reviews: list):
        """Display found product reviews for selection"""
        self.product_reviews_cache = reviews
        self.product_reviews_frame.pack(fill="x")
        
        self.product_reviews_list.delete("1.0", "end")
        for i, review in enumerate(reviews[:10], 1):  # Show max 10
            rating = getattr(review, 'rating', 'N/A')
            title = getattr(review, 'title', '')[:35]
            review_id = getattr(review, 'review_id', 'N/A')[:12]
            self.product_reviews_list.insert(
                "end",
                f"{i}. [{rating}★] {review_id}... - {title}...\n"
            )
        
        if len(reviews) > 10:
            self.product_reviews_list.insert("end", f"\n... and {len(reviews) - 10} more")
    
    def get_selected_product_review(self):
        """Get the selected review from product search results"""
        if not self.product_reviews_cache:
            return None
        
        try:
            idx = int(self.product_review_select.get() or "1") - 1
            if 0 <= idx < len(self.product_reviews_cache):
                return self.product_reviews_cache[idx]
        except ValueError:
            pass
        
        return self.product_reviews_cache[0] if self.product_reviews_cache else None
        
    def _on_speed_change(self, choice):
        """Handle animation speed change"""
        speeds = {"Slow": 1.0, "Normal": 0.5, "Fast": 0.2}
        self._animation_speed = speeds.get(choice, 0.5)
    
    def display_proof(self, proof: list, leaf_hash: str, index: int, root_hash: str = None,
                      review_id: str = None, product_id: str = None):
        """Display generated proof"""
        self.current_proof = proof
        self.current_leaf_hash = leaf_hash
        self.current_root_hash = root_hash
        
        self.proof_text.delete("1.0", "end")
        
        # Show appropriate header based on search mode
        if review_id:
            self.proof_text.insert("end", f"Proof for Review ID: {review_id[:20]}...\n")
        elif product_id:
            self.proof_text.insert("end", f"Proof for Product: {product_id} (idx {index})\n")
        else:
            self.proof_text.insert("end", f"Proof for index {index}:\n")
        
        self.proof_text.insert("end", f"Leaf hash: {leaf_hash[:48]}...\n\n")
        self.proof_text.insert("end", f"Proof path ({len(proof)} steps):\n")
        self.proof_text.insert("end", "-" * 55 + "\n")
        
        for i, (sibling_hash, direction) in enumerate(proof):
            arrow = "←" if direction == "L" else "→"
            dir_name = "LEFT" if direction == "L" else "RIGHT"
            self.proof_text.insert(
                "end",
                f"Step {i+1}: {arrow} {dir_name:5} | {sibling_hash[:40]}...\n"
            )
        
        self.result_label.configure(text="", text_color="#ffffff")
        self.anim_status.delete("1.0", "end")
        self.anim_status.insert("end", "Click 'Animate Verification' to see the proof path.\n")
        
        # Draw initial visualization
        self._draw_proof_path_static()
    
    def _draw_proof_path_static(self):
        """Draw static proof path visualization"""
        self.anim_canvas.delete("all")
        
        if not self.current_proof:
            return
        
        # Canvas dimensions
        width = self.anim_canvas.winfo_width() or 400
        height = self.anim_canvas.winfo_height() or 180
        
        # Draw nodes for proof path
        num_steps = len(self.current_proof) + 1  # +1 for leaf
        if num_steps == 0:
            return
        
        node_spacing = min(70, (width - 40) / max(num_steps, 1))
        start_x = 30
        center_y = height // 2
        
        # Draw leaf node
        x = start_x
        self.anim_canvas.create_oval(
            x - 20, center_y - 20, x + 20, center_y + 20,
            fill="#4a9eff", outline="#ffffff", width=2, tags="leaf"
        )
        self.anim_canvas.create_text(
            x, center_y, text="Leaf", fill="white", font=("Segoe UI", 8, "bold")
        )
        self.anim_canvas.create_text(
            x, center_y + 35, text=self.current_leaf_hash[:8] + "...",
            fill="#888888", font=("Consolas", 7)
        )
        
        prev_x = x
        
        # Draw proof step nodes
        for i, (sibling_hash, direction) in enumerate(self.current_proof):
            x = start_x + (i + 1) * node_spacing
            
            # Draw sibling (smaller, offset)
            sibling_y = center_y - 45 if direction == "L" else center_y + 45
            self.anim_canvas.create_oval(
                x - 15 - 20, sibling_y - 15, x - 15 + 15, sibling_y + 15,
                fill="#555555", outline="#888888", width=1, tags=f"sibling_{i}"
            )
            dir_symbol = "L" if direction == "L" else "R"
            self.anim_canvas.create_text(
                x - 15, sibling_y, text=dir_symbol, fill="#888888", font=("Segoe UI", 7)
            )
            
            # Draw parent node
            self.anim_canvas.create_oval(
                x - 20, center_y - 20, x + 20, center_y + 20,
                fill="#4a9eff", outline="#ffffff", width=2, tags=f"parent_{i}"
            )
            self.anim_canvas.create_text(
                x, center_y, text=f"H{i+1}", fill="white", font=("Segoe UI", 8, "bold")
            )
            
            # Draw edge from previous to current
            self.anim_canvas.create_line(
                prev_x + 20, center_y, x - 20, center_y,
                fill="#555555", width=2, arrow="last", tags=f"edge_{i}"
            )
            
            # Draw edge from sibling to parent
            self.anim_canvas.create_line(
                x - 15, sibling_y + (15 if direction == "L" else -15),
                x - 5, center_y + (-15 if direction == "L" else 15),
                fill="#555555", width=1, dash=(3, 2), tags=f"sibling_edge_{i}"
            )
            
            prev_x = x
        
        # Draw root indicator
        x = start_x + num_steps * node_spacing
        self.anim_canvas.create_text(
            prev_x + 40, center_y, text="→ Root",
            fill="#1dd1a1", font=("Segoe UI", 10, "bold")
        )
    
    def animate_proof(self, tree_canvas: AnimatedCanvas = None):
        """Start animated proof verification"""
        if not self.current_proof or not self.current_leaf_hash:
            return
        
        self.animation_running = True
        self.animate_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        
        def update_status(text):
            self.anim_status.delete("1.0", "end")
            self.anim_status.insert("end", text)
            self.anim_status.update()
        
        def animation_thread():
            import hashlib
            
            # Colors
            LEAF_COLOR = "#ff6b6b"
            SIBLING_COLOR = "#feca57"
            COMPUTING_COLOR = "#48dbfb"
            VERIFIED_COLOR = "#1dd1a1"
            
            current_hash = self.current_leaf_hash
            
            # Highlight leaf
            update_status(
                f"🔵 Starting verification...\n\n"
                f"Leaf hash:\n{current_hash[:48]}..."
            )
            self.anim_canvas.itemconfig("leaf", fill=LEAF_COLOR)
            self.anim_canvas.update()
            time.sleep(self._animation_speed)
            
            # Process each step
            for i, (sibling_hash, direction) in enumerate(self.current_proof):
                if not self.animation_running:
                    break
                
                dir_name = "LEFT" if direction == "L" else "RIGHT"
                
                # Highlight sibling
                update_status(
                    f"Step {i+1}/{len(self.current_proof)}\n\n"
                    f"Combining with {dir_name} sibling:\n"
                    f"{sibling_hash[:40]}..."
                )
                self.anim_canvas.itemconfig(f"sibling_{i}", fill=SIBLING_COLOR, outline="#ffffff")
                self.anim_canvas.itemconfig(f"sibling_edge_{i}", fill=SIBLING_COLOR, width=2)
                self.anim_canvas.update()
                time.sleep(self._animation_speed * 0.6)
                
                # Compute hash
                if direction == "L":
                    combined = sibling_hash + current_hash
                else:
                    combined = current_hash + sibling_hash
                
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                
                # Show computing
                update_status(
                    f"Step {i+1}/{len(self.current_proof)}\n\n"
                    f"Computing: SHA256({'sibling + current' if direction == 'L' else 'current + sibling'})\n"
                    f"Result:\n{new_hash[:40]}..."
                )
                self.anim_canvas.itemconfig(f"parent_{i}", fill=COMPUTING_COLOR)
                self.anim_canvas.itemconfig(f"edge_{i}", fill=COMPUTING_COLOR, width=3)
                self.anim_canvas.update()
                time.sleep(self._animation_speed * 0.4)
                
                # Mark verified
                self.anim_canvas.itemconfig(f"parent_{i}", fill=VERIFIED_COLOR)
                self.anim_canvas.itemconfig(f"edge_{i}", fill=VERIFIED_COLOR)
                self.anim_canvas.update()
                
                current_hash = new_hash
                time.sleep(self._animation_speed * 0.3)
            
            # Final verification
            if self.animation_running:
                verified = (self.current_root_hash is None or 
                           current_hash == self.current_root_hash)
                
                if verified:
                    update_status(
                        f"✅ VERIFICATION COMPLETE!\n\n"
                        f"Computed root:\n{current_hash[:40]}...\n\n"
                        f"Proof is VALID!"
                    )
                    self.result_label.configure(
                        text="✅ Proof Verified Successfully!",
                        text_color="#1dd1a1"
                    )
                else:
                    update_status(
                        f"❌ VERIFICATION FAILED!\n\n"
                        f"Computed: {current_hash[:32]}...\n"
                        f"Expected: {self.current_root_hash[:32] if self.current_root_hash else 'N/A'}..."
                    )
                    self.result_label.configure(
                        text="❌ Proof Verification Failed!",
                        text_color="#e74c3c"
                    )
                
                # Also animate on tree canvas if provided
                if tree_canvas and hasattr(tree_canvas, 'animate_proof_verification'):
                    tree_canvas.animate_proof_verification(
                        self.current_leaf_hash,
                        self.current_proof,
                        self.current_root_hash or current_hash,
                        status_callback=None,
                        complete_callback=None
                    )
            
            self.animation_running = False
            self.animate_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
        
        self._animation_thread = threading.Thread(target=animation_thread, daemon=True)
        self._animation_thread.start()
    
    def stop_animation(self):
        """Stop the current animation"""
        self.animation_running = False
        self.animate_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.anim_status.insert("end", "\n\n⏹️ Animation stopped by user.")
    
    def show_result(self, success: bool, time_ms: float = 0):
        """Show verification result"""
        if success:
            self.result_label.configure(
                text=f"✅ Proof verified successfully! ({time_ms:.3f}ms)",
                text_color="#2ecc71"
            )
        else:
            self.result_label.configure(
                text="❌ Proof verification failed!",
                text_color="#e74c3c"
            )


class TamperPanel(ctk.CTkFrame):
    """Tamper detection and simulation panel"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Title
        ctk.CTkLabel(
            self, text="🔧 Tamper Detection & Simulation",
            font=("Segoe UI", 20, "bold")
        ).pack(pady=20)
        
        # Two columns
        columns = ctk.CTkFrame(self, fg_color="transparent")
        columns.pack(fill="both", expand=True, padx=20, pady=10)
        columns.columnconfigure(0, weight=1)
        columns.columnconfigure(1, weight=1)
        
        # Left: Simulation
        sim_frame = ctk.CTkFrame(columns)
        sim_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(
            sim_frame, text="🎭 Tamper Simulation",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=15)
        
        # Tamper type selection
        ctk.CTkLabel(
            sim_frame, text="Select Tamper Type:",
            font=("Segoe UI", 12)
        ).pack(anchor="w", padx=15, pady=5)
        
        self.tamper_type_var = ctk.StringVar(value="modify")
        
        types_frame = ctk.CTkFrame(sim_frame, fg_color="transparent")
        types_frame.pack(fill="x", padx=15, pady=5)
        
        tamper_types = [
            ("modify", "✏️ Modify"),
            ("delete", "🗑️ Delete"),
            ("insert", "➕ Insert"),
            ("reorder", "🔀 Reorder"),
        ]
        
        for value, text in tamper_types:
            ctk.CTkRadioButton(
                types_frame, text=text,
                variable=self.tamper_type_var, value=value,
                font=("Segoe UI", 11)
            ).pack(anchor="w", pady=3)
        
        # Target index
        ctk.CTkLabel(
            sim_frame, text="Target Index:",
            font=("Segoe UI", 12)
        ).pack(anchor="w", padx=15, pady=(15, 5))
        
        self.target_entry = ctk.CTkEntry(
            sim_frame, placeholder_text="e.g., 0",
            height=35, font=("Segoe UI", 11)
        )
        self.target_entry.pack(fill="x", padx=15, pady=5)
        
        self.simulate_btn = ctk.CTkButton(
            sim_frame, text="🚀 Simulate Tamper",
            fg_color="#e74c3c", hover_color="#c0392b",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.simulate_btn.pack(fill="x", padx=15, pady=15)
        
        # Right: Detection
        detect_frame = ctk.CTkFrame(columns)
        detect_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(
            detect_frame, text="🔍 Detection Results",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=15)
        
        self.detect_text = ctk.CTkTextbox(detect_frame, height=250, font=("Consolas", 10))
        self.detect_text.pack(fill="both", expand=True, padx=15, pady=10)
        
        self.detect_btn = ctk.CTkButton(
            detect_frame, text="🔍 Run Detection",
            fg_color="#3498db", hover_color="#2980b9",
            height=40, font=("Segoe UI", 12, "bold")
        )
        self.detect_btn.pack(fill="x", padx=15, pady=15)
        
        # Result
        self.result_label = ctk.CTkLabel(
            self, text="",
            font=("Segoe UI", 14, "bold")
        )
        self.result_label.pack(pady=10)


class PerformancePanel(ctk.CTkFrame):
    """Performance metrics and benchmarking panel"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Title
        ctk.CTkLabel(
            self, text="📊 Performance Metrics",
            font=("Segoe UI", 20, "bold")
        ).pack(pady=20)
        
        # Metrics cards
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20, pady=10)
        
        self.metric_cards = {}
        metrics = [
            ("build_time", "🏗️ Build Time", "N/A", "#3498db"),
            ("proof_time", "🔑 Proof Gen", "N/A", "#2ecc71"),
            ("verify_time", "✅ Verify Time", "N/A", "#9b59b6"),
            ("memory", "💾 Memory", "N/A", "#e74c3c"),
        ]
        
        for i, (key, title, value, color) in enumerate(metrics):
            card = self._create_metric_card(cards_frame, title, value, color)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            self.metric_cards[key] = card
            cards_frame.columnconfigure(i, weight=1)
        
        # Benchmark button
        self.benchmark_btn = ctk.CTkButton(
            self, text="🚀 Run Full Benchmark",
            fg_color="#e74c3c", hover_color="#c0392b",
            height=50, font=("Segoe UI", 14, "bold"),
            width=300
        )
        self.benchmark_btn.pack(pady=20)
        
        # Results
        results_frame = ctk.CTkFrame(self)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(
            results_frame, text="📋 Benchmark Results:",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=10, pady=10)
        
        self.results_text = ctk.CTkTextbox(results_frame, height=200, font=("Consolas", 10))
        self.results_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Export button
        self.export_btn = ctk.CTkButton(
            self, text="💾 Export Metrics",
            fg_color="#2ecc71", hover_color="#27ae60",
            height=40, font=("Segoe UI", 12, "bold"),
            width=200
        )
        self.export_btn.pack(pady=10)
    
    def _create_metric_card(self, parent, title: str, value: str, color: str):
        """Create a metric card"""
        card = ctk.CTkFrame(parent, fg_color="#2d2d44", corner_radius=15)
        
        ctk.CTkLabel(
            card, text=title,
            font=("Segoe UI", 11), text_color="#aaaaaa"
        ).pack(pady=(15, 5))
        
        value_label = ctk.CTkLabel(
            card, text=value,
            font=("Segoe UI", 18, "bold"), text_color=color
        )
        value_label.pack(pady=(5, 15))
        card.value_label = value_label
        
        return card
    
    def update_metric(self, key: str, value: str):
        """Update a metric value"""
        if key in self.metric_cards:
            self.metric_cards[key].value_label.configure(text=value)
    
    def show_results(self, metrics: dict):
        """Display benchmark results"""
        self.results_text.delete("1.0", "end")
        
        self.results_text.insert("end", "=" * 60 + "\n")
        self.results_text.insert("end", "BENCHMARK RESULTS\n")
        self.results_text.insert("end", "=" * 60 + "\n\n")
        
        for key, value in metrics.items():
            if isinstance(value, float):
                self.results_text.insert("end", f"{key}: {value:.4f}\n")
            else:
                self.results_text.insert("end", f"{key}: {value}\n")


class MerkleTreeGUI(ctk.CTk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        self.title("🌳 Merkle Tree Integrity Verification System")
        self.geometry("1400x900")
        self.minsize(1200, 700)
        
        # Data
        self.reviews: List[Review] = []
        self.tree: Optional[MerkleTree] = None
        self.verifier = IntegrityVerifier()
        self.detector: Optional[TamperDetector] = None
        self.monitor = PerformanceMonitor()
        self.current_file = ""
        
        self._create_ui()
        self._bind_events()
        
    def _create_ui(self):
        """Create the main UI"""
        # Main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab view
        self.tabview = ctk.CTkTabview(main_container)
        self.tabview.pack(fill="both", expand=True)
        
        # Create tabs
        self.tab_dashboard = self.tabview.add("📊 Dashboard")
        self.tab_tree = self.tabview.add("🌳 Tree View")
        self.tab_integrity = self.tabview.add("🔒 Integrity")
        self.tab_proofs = self.tabview.add("🔐 Proofs")
        self.tab_tamper = self.tabview.add("🔧 Tampering")
        self.tab_performance = self.tabview.add("📈 Performance")
        
        # Initialize panels
        self.dashboard = DashboardPanel(self.tab_dashboard)
        self.dashboard.pack(fill="both", expand=True)
        
        self.tree_viz = TreeVisualizer(self.tab_tree)
        self.tree_viz.pack(fill="both", expand=True)
        
        self.integrity = IntegrityPanel(self.tab_integrity)
        self.integrity.pack(fill="both", expand=True)
        
        self.proofs = ProofPanel(self.tab_proofs)
        self.proofs.pack(fill="both", expand=True)
        
        self.tamper = TamperPanel(self.tab_tamper)
        self.tamper.pack(fill="both", expand=True)
        
        self.performance = PerformancePanel(self.tab_performance)
        self.performance.pack(fill="both", expand=True)
        
        # Status bar
        self.status_bar = ctk.CTkFrame(self, height=30)
        self.status_bar.pack(fill="x", side="bottom")
        
        self.status_label = ctk.CTkLabel(
            self.status_bar, text="Ready",
            font=("Segoe UI", 11)
        )
        self.status_label.pack(side="left", padx=10)
        
        self.memory_label = ctk.CTkLabel(
            self.status_bar, text="Memory: --",
            font=("Segoe UI", 11)
        )
        self.memory_label.pack(side="right", padx=10)
        
    def _bind_events(self):
        """Bind button events"""
        # Dashboard quick actions
        self.dashboard.quick_buttons["load"].configure(command=self.load_data)
        self.dashboard.quick_buttons["build"].configure(command=self.build_tree)
        self.dashboard.quick_buttons["verify"].configure(command=self.quick_verify)
        self.dashboard.quick_buttons["benchmark"].configure(command=self.run_benchmark)
        
        # Integrity panel
        self.integrity.save_btn.configure(command=self.save_root)
        self.integrity.verify_btn.configure(command=self.verify_integrity)
        self.integrity.compare_btn.configure(command=self.compare_roots)
        
        # Proofs panel
        self.proofs.generate_btn.configure(command=self.generate_proof)
        self.proofs.verify_btn.configure(command=self.verify_proof)
        self.proofs.animate_btn.configure(command=self.animate_proof)
        self.proofs.stop_btn.configure(command=self.stop_proof_animation)
        self.proofs.search_product_btn.configure(command=self.search_product)
        
        # Tamper panel
        self.tamper.simulate_btn.configure(command=self.simulate_tamper)
        self.tamper.detect_btn.configure(command=self.detect_tamper)
        
        # Performance panel
        self.performance.benchmark_btn.configure(command=self.run_benchmark)
        self.performance.export_btn.configure(command=self.export_metrics)
    
    def set_status(self, message: str):
        """Update status bar"""
        self.status_label.configure(text=message)
        self.dashboard.log(message)
        self.update()
    
    def load_data(self):
        """Load data from JSON file"""
        filepath = filedialog.askopenfilename(
            title="Select Data File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir="data"
        )
        
        if not filepath:
            return
        
        self.current_file = filepath
        
        # Create progress window
        progress = ProgressWindow(self, "Loading Data")
        
        def load_thread():
            try:
                # Get directory and filename
                data_dir = os.path.dirname(filepath)
                filename = os.path.basename(filepath)
                
                progress.update_progress(0.1, "Counting records...")
                
                # Count total records
                total = 0
                with open(filepath, 'r', encoding='utf-8') as f:
                    for _ in f:
                        total += 1
                
                progress.update_progress(0.2, f"Found {total:,} records")
                
                # Create loader and load reviews
                loader = DataLoader(data_dir)
                self.reviews = []
                
                # Use streaming to show progress
                for i, review in enumerate(loader.stream_reviews(filename)):
                    self.reviews.append(review)
                    if i % 10000 == 0:
                        prog = 0.2 + (i / total) * 0.7
                        progress.update_progress(
                            prog, 
                            "Loading reviews...",
                            f"{i:,} / {total:,}"
                        )
                
                final_count = len(self.reviews)
                progress.update_progress(1.0, "Complete!")
                time.sleep(0.3)
                
                # Safely destroy progress window from main thread
                self.after(0, progress.destroy)
                
                # Update UI
                self.after(100, lambda: self._update_after_load(filepath, final_count))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, progress.destroy)
                self.after(100, lambda msg=error_msg: messagebox.showerror("Error", msg))
        
        threading.Thread(target=load_thread, daemon=True).start()
    
    def _update_after_load(self, filepath: str, count: int):
        """Update UI after data load"""
        filename = os.path.basename(filepath)
        self.dashboard.update_card("data", f"{count:,} reviews", "#2ecc71")
        self.set_status(f"Loaded {count:,} reviews from {filename}")
        
        # Update memory
        import psutil
        process = psutil.Process()
        mem_mb = process.memory_info().rss / 1024 / 1024
        self.memory_label.configure(text=f"Memory: {mem_mb:.1f} MB")
        
        # Set sample data for proof panel
        self.proofs.set_sample_data(self.reviews)
    
    def build_tree(self):
        """Build Merkle tree from loaded data"""
        if not self.reviews:
            messagebox.showwarning("Warning", "Please load data first!")
            return
        
        progress = ProgressWindow(self, "Building Merkle Tree")
        
        def build_thread():
            try:
                progress.update_progress(0.1, "Initializing tree...")
                
                build_start = time.perf_counter()
                self.tree = MerkleTree()
                
                progress.update_progress(0.3, "Building tree...")
                
                # Build tree directly with reviews (no add_leaf)
                self.tree.build(self.reviews, show_progress=False)
                
                build_time = time.perf_counter() - build_start
                
                progress.update_progress(1.0, "Complete!")
                time.sleep(0.3)
                
                # Safely destroy progress window from main thread
                self.after(0, progress.destroy)
                
                # Update UI
                self.after(100, lambda: self._update_after_build(build_time))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, progress.destroy)
                self.after(100, lambda msg=error_msg: messagebox.showerror("Error", msg))
        
        threading.Thread(target=build_thread, daemon=True).start()
    
    def _update_after_build(self, build_time: float):
        """Update UI after tree build"""
        root_hash = self.tree.root.hash if self.tree.root else "N/A"
        
        self.dashboard.update_card("tree", f"Built ({build_time:.2f}s)", "#2ecc71")
        self.set_status(f"Tree built in {build_time:.2f}s | Root: {root_hash[:16]}...")
        
        # Update tree visualization
        self.tree_viz.set_tree(self.tree)
        
        # Update integrity panel
        self.integrity.set_root(root_hash)
        
        # Create detector
        self.detector = TamperDetector(self.tree, self.reviews.copy())
        
        # Update performance
        self.performance.update_metric("build_time", f"{build_time:.3f}s")
        
        # Update memory
        import psutil
        process = psutil.Process()
        mem_mb = process.memory_info().rss / 1024 / 1024
        self.memory_label.configure(text=f"Memory: {mem_mb:.1f} MB")
        self.performance.update_metric("memory", f"{mem_mb:.1f} MB")
    
    def save_root(self):
        """Save current root hash"""
        if not self.tree or not self.tree.root:
            messagebox.showwarning("Warning", "Please build tree first!")
            return
        
        dataset_name = os.path.basename(self.current_file) if self.current_file else "unknown"
        
        self.verifier.save_root(
            self.tree.root.hash,
            dataset_name,
            len(self.reviews),
            self.tree.height
        )
        
        # Update saved roots display
        roots = self.verifier.get_root_history(dataset_name)
        self.integrity.update_saved_roots(roots)
        
        self.set_status("Root hash saved successfully")
        self.integrity.show_result(True, "Root hash saved!")
    
    def verify_integrity(self):
        """Verify current root against saved"""
        if not self.tree or not self.tree.root:
            messagebox.showwarning("Warning", "Please build tree first!")
            return
        
        dataset_name = os.path.basename(self.current_file) if self.current_file else "unknown"
        result = self.verifier.verify_integrity(self.tree.root.hash, dataset_name)
        
        if result.get('integrity_verified') == True:
            self.integrity.show_result(True, "Integrity verified - root matches!")
            self.dashboard.update_card("integrity", "✅ Verified", "#2ecc71")
        elif result.get('integrity_verified') == False:
            self.integrity.show_result(False, "Integrity check failed - root mismatch!")
            self.dashboard.update_card("integrity", "❌ Failed", "#e74c3c")
        else:
            self.integrity.show_result(False, result.get('message', 'No baseline found'))
            self.dashboard.update_card("integrity", "⚠️ No baseline", "#f39c12")
    
    def compare_roots(self):
        """Compare two root hashes"""
        dataset_name = os.path.basename(self.current_file) if self.current_file else "unknown"
        roots = self.verifier.get_root_history(dataset_name)
        if len(roots) < 2:
            messagebox.showinfo("Info", "Need at least 2 saved roots to compare")
            return
        
        # Simple comparison of last two
        root1 = roots[-1]
        root2 = roots[-2]
        
        match = root1.get('root_hash') == root2.get('root_hash')
        
        if match:
            self.integrity.show_result(True, "Roots match!")
        else:
            self.integrity.show_result(False, "Roots differ!")
    
    def quick_verify(self):
        """Quick verification from dashboard"""
        if self.tree and self.tree.root:
            self.verify_integrity()
        else:
            messagebox.showinfo("Info", "Please build tree first")
    
    def generate_proof(self):
        """Generate membership proof based on search mode (index, review_id, or product_id)"""
        if not self.tree or not self.tree.root:
            messagebox.showwarning("Warning", "Please build tree first!")
            return
        
        search_mode = self.proofs.get_search_mode()
        review = None
        index = None
        review_id = None
        product_id = None
        
        if search_mode == "index":
            # Search by index
            try:
                index = int(self.proofs.index_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid index")
                return
            
            if index < 0 or index >= len(self.reviews):
                messagebox.showerror("Error", f"Index must be 0-{len(self.reviews)-1}")
                return
            
            review = self.reviews[index]
            review_id = review.review_id
            
        elif search_mode == "review_id":
            # Search by Review ID
            search_id = self.proofs.review_id_entry.get().strip()
            if not search_id:
                messagebox.showerror("Error", "Please enter a Review ID")
                return
            
            # Find review by ID
            review = None
            for i, r in enumerate(self.reviews):
                if r.review_id == search_id or r.review_id.startswith(search_id):
                    review = r
                    index = i
                    break
            
            if not review:
                messagebox.showerror("Error", f"Review ID '{search_id}' not found in dataset")
                return
            
            review_id = review.review_id
            
        elif search_mode == "product_id":
            # Search by Product ID (ASIN)
            selected_review = self.proofs.get_selected_product_review()
            if not selected_review:
                messagebox.showerror("Error", "Please search for a product and select a review first")
                return
            
            review = selected_review
            review_id = review.review_id
            product_id = getattr(review, 'asin', None)
            
            # Find index
            for i, r in enumerate(self.reviews):
                if r.review_id == review_id:
                    index = i
                    break
        
        if not review:
            messagebox.showerror("Error", "Could not find review")
            return
        
        # Generate proof
        gen_start = time.perf_counter()
        proof = self.tree.generate_proof(review_id)
        gen_time = time.perf_counter() - gen_start
        
        if not proof:
            messagebox.showerror("Error", f"Could not generate proof for review {review_id[:16]}...")
            return
        
        leaf_hash = review.raw_hash or review.compute_hash()
        root_hash = self.tree.root.hash
        
        # Display proof with appropriate context
        self.proofs.display_proof(
            proof, leaf_hash, index, root_hash,
            review_id=review_id if search_mode == "review_id" else None,
            product_id=product_id if search_mode == "product_id" else None
        )
        
        # Store review info for verification
        self.proofs.current_review_id = review_id
        
        # Status message based on search mode
        if search_mode == "review_id":
            self.set_status(f"Proof generated for Review {review_id[:16]}... in {gen_time*1000:.3f}ms")
        elif search_mode == "product_id":
            self.set_status(f"Proof generated for Product {product_id} review in {gen_time*1000:.3f}ms")
        else:
            self.set_status(f"Proof generated for index {index} in {gen_time*1000:.3f}ms")
        
        self.performance.update_metric("proof_time", f"{gen_time*1000:.3f}ms")
    
    def search_product(self):
        """Search for reviews by Product ID (ASIN)"""
        if not self.reviews:
            messagebox.showwarning("Warning", "Please load data first!")
            return
        
        product_id = self.proofs.product_id_entry.get().strip()
        if not product_id:
            messagebox.showerror("Error", "Please enter a Product ID (ASIN)")
            return
        
        # Find reviews for this product
        product_reviews = [r for r in self.reviews if getattr(r, 'asin', '') == product_id]
        
        if not product_reviews:
            messagebox.showinfo("Not Found", f"No reviews found for product '{product_id}'")
            return
        
        # Show the found reviews
        self.proofs.show_product_reviews(product_reviews)
        self.set_status(f"Found {len(product_reviews)} reviews for product {product_id}")
    
    def verify_proof(self):
        """Verify current proof"""
        if not self.proofs.current_proof or not self.proofs.current_leaf_hash:
            messagebox.showwarning("Warning", "Please generate a proof first!")
            return
        
        review_id = getattr(self.proofs, 'current_review_id', 'unknown')
        
        verify_start = time.perf_counter()
        result = self.tree.verify_proof(
            review_id,
            self.proofs.current_leaf_hash,
            self.proofs.current_proof,
            self.tree.root.hash
        )
        verify_time = time.perf_counter() - verify_start
        
        self.proofs.show_result(result, verify_time * 1000)
        self.performance.update_metric("verify_time", f"{verify_time*1000:.3f}ms")
    
    def animate_proof(self):
        """Animate proof verification path"""
        if not self.proofs.current_proof or not self.proofs.current_leaf_hash:
            messagebox.showwarning("Warning", "Please generate a proof first!")
            return
        
        # Start animation in proof panel
        self.proofs.animate_proof(self.tree_viz.canvas if self.tree_viz else None)
        self.set_status("Animating proof verification path...")
    
    def stop_proof_animation(self):
        """Stop proof animation"""
        self.proofs.stop_animation()
        self.set_status("Animation stopped")
    
    def simulate_tamper(self):
        """Simulate tampering"""
        if not self.detector:
            messagebox.showwarning("Warning", "Please build tree first!")
            return
        
        tamper_type_str = self.tamper.tamper_type_var.get()
        
        try:
            target = int(self.tamper.target_entry.get() or "0")
        except ValueError:
            target = 0
        
        # Apply tampering using TamperSimulator static methods
        if tamper_type_str == "modify":
            tampered_data, description = TamperSimulator.modify_record(self.reviews, index=target)
            tamper_type = TamperType.MODIFICATION
        elif tamper_type_str == "delete":
            tampered_data, description = TamperSimulator.delete_record(self.reviews, index=target)
            tamper_type = TamperType.DELETION
        elif tamper_type_str == "insert":
            tampered_data, description = TamperSimulator.insert_record(self.reviews, index=target)
            tamper_type = TamperType.INSERTION
        else:  # reorder - treat as modification
            # Swap two adjacent records
            tampered_data = self.reviews.copy()
            if target < len(tampered_data) - 1:
                tampered_data[target], tampered_data[target + 1] = tampered_data[target + 1], tampered_data[target]
            description = f"Reordered records at index {target}"
            tamper_type = TamperType.MODIFICATION
        
        # Build new tree with tampered data
        tampered_tree = MerkleTree()
        tampered_tree.build(tampered_data, show_progress=False)
        
        # Compare roots
        original_root = self.tree.root.hash
        tampered_root = tampered_tree.root.hash
        
        self.tamper.detect_text.delete("1.0", "end")
        self.tamper.detect_text.insert("end", f"Tamper Type: {tamper_type.value}\n")
        self.tamper.detect_text.insert("end", f"Action: {description}\n\n")
        self.tamper.detect_text.insert("end", f"Original Root:\n{original_root}\n\n")
        self.tamper.detect_text.insert("end", f"Tampered Root:\n{tampered_root}\n\n")
        
        if original_root != tampered_root:
            self.tamper.detect_text.insert("end", "🚨 ROOTS DIFFER - Tampering detected!\n")
            self.tamper.result_label.configure(
                text="🚨 Tampering Successfully Detected!",
                text_color="#2ecc71"
            )
        else:
            self.tamper.result_label.configure(
                text="⚠️ Roots match unexpectedly",
                text_color="#f39c12"
            )
        
        self.set_status(f"Simulated {tamper_type.value} tampering at index {target}")
    
    def detect_tamper(self):
        """Run tamper detection"""
        if not self.detector:
            messagebox.showwarning("Warning", "Please build tree first!")
            return
        
        # Detect tampering by comparing current reviews with original
        result = self.detector.detect_tampering(self.reviews)
        
        # Display result
        self.tamper.detect_text.delete("1.0", "end")
        self.tamper.detect_text.insert("end", f"Detection Result\n")
        self.tamper.detect_text.insert("end", "=" * 40 + "\n\n")
        self.tamper.detect_text.insert("end", f"Tampering Detected: {result.detected}\n")
        self.tamper.detect_text.insert("end", f"Type: {result.tamper_type.value}\n")
        self.tamper.detect_text.insert("end", f"Message: {result.message}\n\n")
        self.tamper.detect_text.insert("end", f"Original Root:\n{result.original_root}\n\n")
        self.tamper.detect_text.insert("end", f"Current Root:\n{result.current_root}\n")
        
        if result.affected_records:
            self.tamper.detect_text.insert("end", f"\nAffected Records:\n")
            for record in result.affected_records:
                self.tamper.detect_text.insert("end", f"  - {record}\n")
        
        if result.detected:
            self.tamper.result_label.configure(
                text="🚨 Tampering Detected!",
                text_color="#e74c3c"
            )
            self.dashboard.update_card("integrity", "❌ Tampered", "#e74c3c")
        else:
            self.tamper.result_label.configure(
                text="✅ Data Integrity Verified",
                text_color="#2ecc71"
            )
            self.dashboard.update_card("integrity", "✅ Intact", "#2ecc71")
    
    def run_benchmark(self):
        """Run full benchmark"""
        if not self.reviews:
            messagebox.showwarning("Warning", "Please load data first!")
            return
        
        progress = ProgressWindow(self, "Running Benchmark")
        
        def benchmark_thread():
            try:
                results = {}
                
                # Tree build benchmark
                progress.update_progress(0.1, "Benchmarking tree build...")
                build_start = time.perf_counter()
                
                bench_tree = MerkleTree()
                sample_size = min(10000, len(self.reviews))
                sample_reviews = self.reviews[:sample_size]
                bench_tree.build(sample_reviews, show_progress=False)
                
                results['tree_build_10k'] = time.perf_counter() - build_start
                
                # Proof generation benchmark
                progress.update_progress(0.4, "Benchmarking proof generation...")
                proof_times = []
                num_proofs = min(100, len(sample_reviews))
                for i in range(num_proofs):
                    review = sample_reviews[i]
                    start = time.perf_counter()
                    bench_tree.generate_proof(review.review_id)
                    proof_times.append(time.perf_counter() - start)
                
                results['avg_proof_gen_ms'] = (sum(proof_times) / len(proof_times)) * 1000
                
                # Verification benchmark
                progress.update_progress(0.7, "Benchmarking verification...")
                verify_times = []
                for i in range(num_proofs):
                    review = sample_reviews[i]
                    proof = bench_tree.generate_proof(review.review_id)
                    leaf_hash = review.raw_hash or review.compute_hash()
                    
                    start = time.perf_counter()
                    bench_tree.verify_proof(review.review_id, leaf_hash, proof, bench_tree.root.hash)
                    verify_times.append(time.perf_counter() - start)
                
                results['avg_verify_ms'] = (sum(verify_times) / len(verify_times)) * 1000
                
                # Memory
                import psutil
                process = psutil.Process()
                results['memory_mb'] = process.memory_info().rss / 1024 / 1024
                
                progress.update_progress(1.0, "Complete!")
                time.sleep(0.3)
                
                # Safely destroy progress window from main thread
                self.after(0, progress.destroy)
                
                self.after(100, lambda: self._show_benchmark_results(results))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, progress.destroy)
                self.after(100, lambda msg=error_msg: messagebox.showerror("Error", msg))
        
        threading.Thread(target=benchmark_thread, daemon=True).start()
    
    def _show_benchmark_results(self, results: dict):
        """Display benchmark results"""
        self.performance.show_results(results)
        
        self.performance.update_metric("build_time", f"{results['tree_build_10k']:.3f}s")
        self.performance.update_metric("proof_time", f"{results['avg_proof_gen_ms']:.3f}ms")
        self.performance.update_metric("verify_time", f"{results['avg_verify_ms']:.3f}ms")
        self.performance.update_metric("memory", f"{results['memory_mb']:.1f} MB")
        
        self.dashboard.update_card("performance", f"{results['avg_verify_ms']:.3f}ms", "#2ecc71")
        self.set_status("Benchmark complete!")
    
    def export_metrics(self):
        """Export metrics to JSON"""
        filepath = filedialog.asksaveasfilename(
            title="Export Metrics",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialdir="reports"
        )
        
        if not filepath:
            return
        
        metrics = self.monitor.get_all_metrics()
        
        with open(filepath, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)
        
        self.set_status(f"Metrics exported to {filepath}")
        messagebox.showinfo("Success", f"Metrics exported to {filepath}")


def run_gui():
    """Run the GUI application"""
    app = MerkleTreeGUI()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
