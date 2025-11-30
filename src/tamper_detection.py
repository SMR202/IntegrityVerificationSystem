"""
Tamper Detection Module
Detects modifications, deletions, and insertions in the dataset.
"""

import copy
import random
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from src.data_loader import Review, DataLoader
from src.merkle_tree import MerkleTree
from src.integrity import IntegrityVerifier


class TamperType(Enum):
    """Types of tampering that can be detected."""
    MODIFICATION = "MODIFICATION"
    DELETION = "DELETION"
    INSERTION = "INSERTION"
    NO_TAMPERING = "NO_TAMPERING"


@dataclass
class TamperResult:
    """Result of a tamper detection check."""
    detected: bool
    tamper_type: TamperType
    message: str
    original_root: str
    current_root: str
    affected_records: List[str] = None  # List of affected review IDs
    
    def __post_init__(self):
        if self.affected_records is None:
            self.affected_records = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "tamper_type": self.tamper_type.value,
            "message": self.message,
            "original_root": self.original_root,
            "current_root": self.current_root,
            "affected_records": self.affected_records
        }


class TamperDetector:
    """
    Detects tampering in datasets by comparing Merkle roots.
    
    Features:
    - Detect modifications to existing records
    - Detect deletions of records
    - Detect insertions of new records
    - Simulate tampering for testing
    """
    
    def __init__(self, original_tree: MerkleTree, original_reviews: List[Review]):
        self.original_tree = original_tree
        self.original_reviews = original_reviews
        self.original_root = original_tree.get_root_hash()
    
    def detect_tampering(self, current_reviews: List[Review], 
                         show_progress: bool = False) -> TamperResult:
        """
        Detect if the current dataset has been tampered with.
        
        Args:
            current_reviews: The current list of reviews to check
            show_progress: Whether to show progress during tree building
            
        Returns:
            TamperResult with detection details
        """
        # Build a new tree from current reviews
        current_tree = MerkleTree()
        current_root = current_tree.build(current_reviews, show_progress=show_progress)
        
        # Compare roots
        if current_root == self.original_root:
            return TamperResult(
                detected=False,
                tamper_type=TamperType.NO_TAMPERING,
                message="Data integrity verified - no tampering detected",
                original_root=self.original_root,
                current_root=current_root
            )
        
        # Tampering detected - try to identify type
        original_count = len(self.original_reviews)
        current_count = len(current_reviews)
        
        if current_count < original_count:
            tamper_type = TamperType.DELETION
            message = f"Data tampering detected: {original_count - current_count} record(s) deleted"
        elif current_count > original_count:
            tamper_type = TamperType.INSERTION
            message = f"Data tampering detected: {current_count - original_count} record(s) inserted"
        else:
            tamper_type = TamperType.MODIFICATION
            message = "Data tampering detected: One or more records modified"
        
        # Try to find affected records
        affected = self._find_affected_records(current_reviews)
        
        return TamperResult(
            detected=True,
            tamper_type=tamper_type,
            message=message,
            original_root=self.original_root,
            current_root=current_root,
            affected_records=affected
        )
    
    def _find_affected_records(self, current_reviews: List[Review]) -> List[str]:
        """
        Try to identify which records were affected by tampering.
        This is a basic comparison - for large datasets, this could be optimized.
        """
        affected = []
        
        # Create a map of current reviews by ID
        current_map = {r.review_id: r for r in current_reviews}
        original_map = {r.review_id: r for r in self.original_reviews}
        
        # Check for modifications and deletions
        for review_id, original in original_map.items():
            if review_id not in current_map:
                affected.append(f"{review_id} (DELETED)")
            else:
                current = current_map[review_id]
                original_hash = original.compute_hash() if not original.raw_hash else original.raw_hash
                current_hash = current.compute_hash()
                if original_hash != current_hash:
                    affected.append(f"{review_id} (MODIFIED)")
        
        # Check for insertions
        for review_id in current_map:
            if review_id not in original_map:
                affected.append(f"{review_id} (INSERTED)")
        
        return affected[:10]  # Return first 10 affected records
    
    def verify_single_record(self, review: Review) -> Tuple[bool, str]:
        """
        Verify a single record exists and hasn't been modified.
        
        Args:
            review: The review to verify
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Check if review exists in tree
        leaf = self.original_tree.get_leaf_by_review_id(review.review_id)
        
        if leaf is None:
            return False, f"Review {review.review_id} not found in dataset"
        
        # Check if hash matches
        current_hash = review.compute_hash()
        if current_hash != leaf.hash:
            return False, f"Review {review.review_id} has been modified"
        
        # Generate and verify proof
        proof = self.original_tree.generate_proof(review.review_id)
        if proof is None:
            return False, f"Could not generate proof for {review.review_id}"
        
        is_valid = self.original_tree.verify_proof(
            review.review_id,
            current_hash,
            proof,
            self.original_root
        )
        
        if is_valid:
            return True, f"Review {review.review_id} verified - exists and unmodified"
        else:
            return False, f"Proof verification failed for {review.review_id}"


class TamperSimulator:
    """
    Simulates various types of tampering for testing purposes.
    """
    
    @staticmethod
    def modify_record(reviews: List[Review], index: int = None, 
                      field: str = "text", new_value: str = None) -> Tuple[List[Review], str]:
        """
        Modify a record in the dataset.
        
        Args:
            reviews: Original list of reviews
            index: Index of review to modify (random if None)
            field: Field to modify (text, rating, title)
            new_value: New value for the field
            
        Returns:
            Tuple of (modified reviews list, description of change)
        """
        # Create a deep copy
        modified = []
        for r in reviews:
            new_review = Review(
                review_id=r.review_id,
                asin=r.asin,
                reviewer_id=r.reviewer_id,
                rating=r.rating,
                title=r.title,
                text=r.text,
                timestamp=r.timestamp,
                verified=r.verified,
                helpful_vote=r.helpful_vote
            )
            modified.append(new_review)
        
        if index is None:
            index = random.randint(0, len(modified) - 1)
        
        target = modified[index]
        
        if field == "text":
            original = target.text
            if new_value:
                target.text = new_value
            else:
                # Just change one character
                if target.text:
                    chars = list(target.text)
                    if chars:
                        chars[0] = 'X' if chars[0] != 'X' else 'Y'
                        target.text = ''.join(chars)
                else:
                    target.text = "Modified"
            description = f"Modified text of review {target.review_id}"
            
        elif field == "rating":
            original = target.rating
            target.rating = 1.0 if target.rating != 1.0 else 5.0
            description = f"Modified rating of review {target.review_id} from {original} to {target.rating}"
            
        elif field == "title":
            original = target.title
            target.title = (new_value or "TAMPERED TITLE")
            description = f"Modified title of review {target.review_id}"
        
        else:
            description = f"Unknown field: {field}"
        
        return modified, description
    
    @staticmethod
    def delete_record(reviews: List[Review], index: int = None) -> Tuple[List[Review], str]:
        """
        Delete a record from the dataset.
        
        Args:
            reviews: Original list of reviews
            index: Index of review to delete (random if None)
            
        Returns:
            Tuple of (modified reviews list, description of change)
        """
        modified = reviews.copy()
        
        if index is None:
            index = random.randint(0, len(modified) - 1)
        
        deleted = modified.pop(index)
        description = f"Deleted review {deleted.review_id} at index {index}"
        
        return modified, description
    
    @staticmethod
    def insert_record(reviews: List[Review], index: int = None) -> Tuple[List[Review], str]:
        """
        Insert a fake record into the dataset.
        
        Args:
            reviews: Original list of reviews
            index: Index where to insert (end if None)
            
        Returns:
            Tuple of (modified reviews list, description of change)
        """
        modified = reviews.copy()
        
        # Create a fake review
        fake = Review(
            review_id="RFAKERECORD",
            asin="FAKE123456",
            reviewer_id="FAKEUSER",
            rating=5.0,
            title="Fake Review",
            text="This is a fake review inserted for testing tampering detection.",
            timestamp=0,
            verified=False,
            helpful_vote=0
        )
        
        if index is None:
            modified.append(fake)
            description = f"Inserted fake review {fake.review_id} at end"
        else:
            modified.insert(index, fake)
            description = f"Inserted fake review {fake.review_id} at index {index}"
        
        return modified, description


# Quick test
if __name__ == "__main__":
    from src.data_loader import DataLoader
    
    print("Testing Tamper Detection...\n")
    
    # Load data and build tree
    loader = DataLoader()
    reviews = loader.load_reviews("Video_Games.json", limit=100, show_progress=False)
    
    tree = MerkleTree()
    tree.build(reviews, show_progress=False)
    
    detector = TamperDetector(tree, reviews)
    
    print("=" * 60)
    print("Original Root:", tree.get_root_hash()[:32] + "...")
    print("=" * 60)
    
    # Test 1: No tampering
    print("\n1. Testing with unmodified data...")
    result = detector.detect_tampering(reviews)
    print(f"   Detected: {result.detected}")
    print(f"   Type: {result.tamper_type.value}")
    print(f"   Message: {result.message}")
    
    # Test 2: Modification
    print("\n2. Testing modification detection...")
    modified, desc = TamperSimulator.modify_record(reviews, index=0)
    print(f"   Action: {desc}")
    result = detector.detect_tampering(modified)
    print(f"   Detected: {result.detected}")
    print(f"   Type: {result.tamper_type.value}")
    print(f"   Message: {result.message}")
    
    # Test 3: Deletion
    print("\n3. Testing deletion detection...")
    deleted, desc = TamperSimulator.delete_record(reviews, index=0)
    print(f"   Action: {desc}")
    result = detector.detect_tampering(deleted)
    print(f"   Detected: {result.detected}")
    print(f"   Type: {result.tamper_type.value}")
    print(f"   Message: {result.message}")
    
    # Test 4: Insertion
    print("\n4. Testing insertion detection...")
    inserted, desc = TamperSimulator.insert_record(reviews)
    print(f"   Action: {desc}")
    result = detector.detect_tampering(inserted)
    print(f"   Detected: {result.detected}")
    print(f"   Type: {result.tamper_type.value}")
    print(f"   Message: {result.message}")
    
    # Test 5: Single record verification
    print("\n5. Testing single record verification...")
    is_valid, msg = detector.verify_single_record(reviews[0])
    print(f"   Valid: {is_valid}")
    print(f"   Message: {msg}")
    
    print("\n" + "=" * 60)
    print("All tamper detection tests completed!")
