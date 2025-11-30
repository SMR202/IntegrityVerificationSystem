"""
Merkle Tree Construction Module
Implements a complete Merkle Tree with SHA-256 hashing for integrity verification.
"""

import hashlib
import math
import time
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from tqdm import tqdm

from src.data_loader import Review


@dataclass
class MerkleNode:
    """
    Represents a node in the Merkle Tree.
    
    Attributes:
        hash: The SHA-256 hash stored at this node
        left: Left child node (None for leaf nodes)
        right: Right child node (None for leaf nodes)
        parent: Parent node (None for root)
        data: Original data (only for leaf nodes)
        index: Position index in the tree level
        is_leaf: Whether this is a leaf node
    """
    hash: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    parent: Optional['MerkleNode'] = None
    data: Optional[Review] = None
    index: int = 0
    is_leaf: bool = False
    
    def __repr__(self) -> str:
        node_type = "Leaf" if self.is_leaf else "Internal"
        return f"MerkleNode({node_type}, hash={self.hash[:16]}..., idx={self.index})"


class MerkleTree:
    """
    A complete Merkle Tree implementation using SHA-256 hashing.
    
    Features:
    - Builds tree from list of Review objects
    - Handles non-power-of-2 leaf counts by duplicating the last leaf
    - Provides proof generation for any leaf
    - Supports verification of proofs
    - Tracks build performance metrics
    """
    
    def __init__(self):
        self.root: Optional[MerkleNode] = None
        self.leaves: List[MerkleNode] = []
        self.leaf_index: Dict[str, int] = {}  # review_id -> leaf index
        self.height: int = 0
        self.total_nodes: int = 0
        self.build_time: float = 0.0
        self.hash_count: int = 0
        
    @staticmethod
    def compute_hash(data: str) -> str:
        """Compute SHA-256 hash of a string."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def combine_hashes(left_hash: str, right_hash: str) -> str:
        """Combine two hashes to create parent hash."""
        combined = left_hash + right_hash
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def _create_leaf_node(self, review: Review, index: int) -> MerkleNode:
        """Create a leaf node from a review."""
        # Compute hash of the review data
        review_hash = review.compute_hash()
        self.hash_count += 1
        
        return MerkleNode(
            hash=review_hash,
            data=review,
            index=index,
            is_leaf=True
        )
    
    def _pad_leaves_to_power_of_2(self, leaves: List[MerkleNode]) -> List[MerkleNode]:
        """
        No longer pads to power of 2 - we handle odd-length levels during tree building.
        This method is kept for API compatibility but now just returns the leaves as-is.
        """
        return leaves
    
    def build(self, reviews: List[Review], show_progress: bool = True) -> str:
        """
        Build the Merkle Tree from a list of reviews.
        
        Args:
            reviews: List of Review objects to include in the tree
            show_progress: Whether to show progress bar
            
        Returns:
            The root hash of the constructed tree
        """
        if not reviews:
            raise ValueError("Cannot build tree from empty review list")
        
        start_time = time.time()
        self.hash_count = 0
        
        # Step 1: Create leaf nodes
        if show_progress:
            print("Creating leaf nodes...")
        
        self.leaves = []
        self.leaf_index = {}
        
        iterator = enumerate(reviews)
        if show_progress:
            iterator = tqdm(iterator, total=len(reviews), desc="Hashing reviews")
        
        for idx, review in iterator:
            leaf = self._create_leaf_node(review, idx)
            self.leaves.append(leaf)
            self.leaf_index[review.review_id] = idx
        
        original_leaf_count = len(self.leaves)
        
        # Step 2: No longer padding - we handle odd levels during build
        # (kept for compatibility, now a no-op)
        self.leaves = self._pad_leaves_to_power_of_2(self.leaves)
        
        # Step 3: Build tree bottom-up (handles odd-length levels)
        if show_progress:
            print("Building tree structure...")
        
        current_level = self.leaves
        level_num = 0
        self.total_nodes = len(self.leaves)
        
        while len(current_level) > 1:
            next_level = []
            level_num += 1
            
            num_nodes = len(current_level)
            
            # Show progress for large levels
            num_pairs = (num_nodes + 1) // 2  # ceiling division for pairs
            iterator = range(0, num_nodes, 2)
            if show_progress and num_pairs > 1000:
                iterator = tqdm(iterator, desc=f"Building level {level_num}", total=num_pairs)
            
            for i in iterator:
                left = current_level[i]
                
                # Handle odd node: pair with itself
                if i + 1 < num_nodes:
                    right = current_level[i + 1]
                    is_self_paired = False
                else:
                    # Last odd node: hash with itself
                    right = left
                    is_self_paired = True
                
                # Combine hashes
                parent_hash = self.combine_hashes(left.hash, right.hash)
                self.hash_count += 1
                
                # Create parent node
                parent = MerkleNode(
                    hash=parent_hash,
                    left=left,
                    right=None if is_self_paired else right,  # Mark as self-paired
                    index=len(next_level),
                    is_leaf=False
                )
                
                # Set parent references
                left.parent = parent
                if not is_self_paired:
                    right.parent = parent
                
                next_level.append(parent)
                self.total_nodes += 1
            
            current_level = next_level
        
        # Set root
        self.root = current_level[0]
        self.height = level_num
        self.build_time = time.time() - start_time
        
        if show_progress:
            print(f"\nTree built successfully!")
            print(f"  Root hash: {self.root.hash}")
            print(f"  Height: {self.height}")
            print(f"  Total nodes: {self.total_nodes:,}")
            print(f"  Hash operations: {self.hash_count:,}")
            print(f"  Build time: {self.build_time:.2f} seconds")
        
        return self.root.hash
    
    def add_review(self, review: Review) -> str:
        """
        Dynamically add a new review to the tree with partial rebuild.
        Only updates the affected path from the new leaf to the root,
        achieving O(log n) complexity instead of O(n) for full rebuild.
        
        Args:
            review: The new Review to add
            
        Returns:
            The new root hash after adding the review
        """
        if not self.root:
            # Tree is empty, build with single review
            return self.build([review], show_progress=False)
        
        start_time = time.perf_counter()
        
        # Create the new leaf node
        new_index = len(self.leaves)
        new_leaf = self._create_leaf_node(review, new_index)
        self.leaves.append(new_leaf)
        self.leaf_index[review.review_id] = new_index
        
        # Find the path that needs to be updated
        # We need to traverse up from the rightmost leaf's parent
        # and update all affected nodes
        
        nodes_updated = 0
        
        # If the previous count was odd, the last node was self-paired
        # We need to give it a proper sibling now
        if new_index > 0:
            prev_leaf = self.leaves[new_index - 1]
            
            # Walk up the tree to find where we need to insert
            # The new leaf becomes a sibling to an existing path
            self._insert_leaf_and_update_path(new_leaf, nodes_updated)
        
        update_time = time.perf_counter() - start_time
        
        return self.root.hash
    
    def _insert_leaf_and_update_path(self, new_leaf: MerkleNode, nodes_updated: int):
        """
        Insert a new leaf and update the path to root.
        This handles the partial tree rebuild efficiently.
        """
        # Strategy: Find the rightmost path and update it
        # If current leaf count is even after adding, pair with previous leaf
        # If odd, we need to propagate up
        
        n = len(self.leaves)
        
        if n == 1:
            # First leaf, it becomes the root
            self.root = new_leaf
            self.height = 0
            self.total_nodes = 1
            return
        
        # Find the previous leaf (the one we might pair with)
        prev_leaf = self.leaves[n - 2]
        
        # Check if prev_leaf was self-paired (its parent.right is None)
        if prev_leaf.parent and prev_leaf.parent.right is None:
            # The previous leaf was self-paired, now pair them properly
            parent = prev_leaf.parent
            parent.right = new_leaf
            new_leaf.parent = parent
            
            # Recompute parent hash
            parent.hash = self.combine_hashes(parent.left.hash, new_leaf.hash)
            self.hash_count += 1
            
            # Propagate changes up to root
            self._update_path_to_root(parent)
            self.total_nodes += 1
        else:
            # Need to create new parent nodes up the tree
            # This is the more complex case where tree height might increase
            self._rebuild_from_leaves()
    
    def _update_path_to_root(self, node: MerkleNode):
        """Update all hashes from the given node up to the root."""
        current = node.parent
        
        while current:
            # Recalculate hash based on children
            left_hash = current.left.hash
            right_hash = current.right.hash if current.right else current.left.hash
            current.hash = self.combine_hashes(left_hash, right_hash)
            self.hash_count += 1
            current = current.parent
    
    def _rebuild_from_leaves(self):
        """Rebuild tree structure from current leaves (fallback for complex cases)."""
        # This is used when the tree structure needs significant changes
        # It's still more efficient than rebuilding from reviews
        
        current_level = self.leaves
        level_num = 0
        self.total_nodes = len(self.leaves)
        
        # Clear parent references
        for leaf in self.leaves:
            leaf.parent = None
        
        while len(current_level) > 1:
            next_level = []
            level_num += 1
            num_nodes = len(current_level)
            
            for i in range(0, num_nodes, 2):
                left = current_level[i]
                
                if i + 1 < num_nodes:
                    right = current_level[i + 1]
                    is_self_paired = False
                else:
                    right = left
                    is_self_paired = True
                
                parent_hash = self.combine_hashes(left.hash, right.hash)
                self.hash_count += 1
                
                parent = MerkleNode(
                    hash=parent_hash,
                    left=left,
                    right=None if is_self_paired else right,
                    index=len(next_level),
                    is_leaf=False
                )
                
                left.parent = parent
                if not is_self_paired:
                    right.parent = parent
                
                next_level.append(parent)
                self.total_nodes += 1
            
            current_level = next_level
        
        self.root = current_level[0]
        self.height = level_num
    
    def get_root_hash(self) -> Optional[str]:
        """Get the root hash of the tree."""
        return self.root.hash if self.root else None
    
    def get_leaf_by_review_id(self, review_id: str) -> Optional[MerkleNode]:
        """Get the leaf node for a specific review ID."""
        idx = self.leaf_index.get(review_id)
        if idx is not None and idx < len(self.leaves):
            return self.leaves[idx]
        return None
    
    def get_leaf_by_index(self, index: int) -> Optional[MerkleNode]:
        """Get leaf node by its index."""
        if 0 <= index < len(self.leaves):
            return self.leaves[index]
        return None
    
    def generate_proof(self, review_id: str) -> Optional[List[Tuple[str, str]]]:
        """
        Generate a Merkle proof (audit path) for a review.
        
        Args:
            review_id: The ID of the review to generate proof for
            
        Returns:
            List of (sibling_hash, direction) tuples where direction is 'L' or 'R'
            indicating whether the sibling is on the left or right.
            Returns None if review_id not found.
        """
        leaf = self.get_leaf_by_review_id(review_id)
        if not leaf:
            return None
        
        proof = []
        current = leaf
        
        while current.parent:
            parent = current.parent
            
            # Check if this is a self-paired node (odd node case)
            if parent.right is None:
                # Self-paired: sibling is itself
                sibling_hash = current.hash
                direction = 'R'  # Convention: treat as right sibling
            elif parent.left == current:
                # Current is left child, sibling is on right
                sibling_hash = parent.right.hash
                direction = 'R'
            else:
                # Current is right child, sibling is on left
                sibling_hash = parent.left.hash
                direction = 'L'
            
            proof.append((sibling_hash, direction))
            current = parent
        
        return proof
    
    def verify_proof(self, review_id: str, review_hash: str, 
                     proof: List[Tuple[str, str]], expected_root: str) -> bool:
        """
        Verify a Merkle proof.
        
        Args:
            review_id: The review ID (for logging)
            review_hash: The hash of the review data
            proof: List of (sibling_hash, direction) tuples
            expected_root: The expected root hash
            
        Returns:
            True if proof is valid, False otherwise
        """
        current_hash = review_hash
        
        for sibling_hash, direction in proof:
            if direction == 'L':
                # Sibling is on left, so it comes first
                current_hash = self.combine_hashes(sibling_hash, current_hash)
            else:
                # Sibling is on right, so current comes first
                current_hash = self.combine_hashes(current_hash, sibling_hash)
        
        return current_hash == expected_root
    
    def exists(self, review_id: str) -> Tuple[bool, Optional[List[Tuple[str, str]]]]:
        """
        Check if a review exists and return its proof.
        
        Args:
            review_id: The review ID to check
            
        Returns:
            Tuple of (exists: bool, proof: Optional[List])
        """
        proof = self.generate_proof(review_id)
        return (proof is not None, proof)
    
    def get_tree_stats(self) -> Dict[str, Any]:
        """Get statistics about the tree."""
        return {
            "root_hash": self.root.hash if self.root else None,
            "height": self.height,
            "total_nodes": self.total_nodes,
            "leaf_count": len(self.leaves),
            "original_reviews": len(self.leaf_index),
            "hash_operations": self.hash_count,
            "build_time_seconds": self.build_time
        }
    
    def visualize_proof_path(self, proof: List[Tuple[str, str]], 
                             leaf_hash: str) -> str:
        """
        Create a text visualization of a proof path.
        
        Args:
            proof: The proof path
            leaf_hash: The starting leaf hash
            
        Returns:
            String representation of the proof path
        """
        lines = []
        lines.append("Proof Path Visualization:")
        lines.append("=" * 50)
        lines.append(f"Leaf: {leaf_hash[:16]}...")
        
        current_hash = leaf_hash
        for i, (sibling, direction) in enumerate(proof):
            if direction == 'L':
                left_hash = sibling[:16]
                right_hash = current_hash[:16]
                current_hash = self.combine_hashes(sibling, current_hash)
            else:
                left_hash = current_hash[:16]
                right_hash = sibling[:16]
                current_hash = self.combine_hashes(current_hash, sibling)
            
            lines.append(f"\nLevel {i + 1}:")
            lines.append(f"  [{left_hash}...] + [{right_hash}...]")
            lines.append(f"  → Parent: {current_hash[:16]}...")
        
        lines.append("\n" + "=" * 50)
        lines.append(f"Root: {current_hash[:16]}...")
        
        return "\n".join(lines)


# Quick test
if __name__ == "__main__":
    from src.data_loader import DataLoader
    
    print("Testing Merkle Tree with 1000 reviews...\n")
    
    # Load data
    loader = DataLoader()
    reviews = loader.load_reviews("Video_Games.json", limit=1000, show_progress=True)
    
    # Build tree
    print("\n" + "=" * 50)
    tree = MerkleTree()
    root_hash = tree.build(reviews, show_progress=True)
    
    # Test proof generation
    print("\n" + "=" * 50)
    print("Testing proof generation...")
    
    test_review = reviews[42]  # Pick a random review
    print(f"\nGenerating proof for review: {test_review.review_id}")
    
    proof = tree.generate_proof(test_review.review_id)
    if proof:
        print(f"Proof length: {len(proof)} hashes")
        print(f"Expected length (log2 of leaves): {math.log2(len(tree.leaves)):.0f}")
        
        # Verify proof
        is_valid = tree.verify_proof(
            test_review.review_id,
            test_review.raw_hash,
            proof,
            root_hash
        )
        print(f"Proof verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
        
        # Visualize
        print("\n" + tree.visualize_proof_path(proof, test_review.raw_hash))
    
    # Test non-existent review
    print("\n" + "=" * 50)
    print("Testing non-existent review...")
    exists, proof = tree.exists("R99999999999")
    print(f"Review R99999999999 exists: {exists}")
    
    # Print tree stats
    print("\n" + "=" * 50)
    print("Tree Statistics:")
    stats = tree.get_tree_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
