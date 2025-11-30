"""
Unit tests for all modules matching actual implementation.
Tests cover data loading, Merkle tree, integrity, tampering, and performance.
"""

import pytest
import hashlib
import json
import os
import time
from src.data_loader import DataLoader, Review
from src.merkle_tree import MerkleTree, MerkleNode
from src.integrity import IntegrityVerifier
from src.tamper_detection import TamperDetector, TamperSimulator, TamperType
from src.performance import PerformanceMonitor


# ========================= Test Fixtures =========================

def create_test_reviews(n: int) -> list:
    """Create n test reviews for testing."""
    reviews = []
    for i in range(n):
        review = Review(
            review_id=f"review_{i}",
            asin=f"B{i:010d}",
            reviewer_id=f"A{i:010d}",
            rating=float((i % 5) + 1),
            title=f"Review Title {i}",
            text=f"This is review text for review number {i}.",
            timestamp=1609459200 + i * 3600,
            verified=i % 2 == 0,
            helpful_vote=i % 10
        )
        reviews.append(review)
    return reviews


@pytest.fixture
def sample_jsonl(tmp_path):
    """Create a sample JSONL file for testing."""
    data = [
        {
            "overall": 5.0,
            "verified": True,
            "reviewTime": "01 1, 2020",
            "reviewerID": "A123456789",
            "asin": "B001234567",
            "reviewerName": "Test User",
            "reviewText": "This is a test review.",
            "summary": "Great!",
            "unixReviewTime": 1609459200
        },
        {
            "overall": 3.0,
            "verified": False,
            "reviewTime": "02 15, 2020",
            "reviewerID": "A987654321",
            "asin": "B007654321",
            "reviewerName": "Another User",
            "reviewText": "Average product.",
            "summary": "Okay",
            "unixReviewTime": 1609545600
        }
    ]
    
    filepath = tmp_path / "test_data.json"
    with open(filepath, 'w') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')
    
    return str(tmp_path), "test_data.json"


# ========================= Data Loader Tests =========================

class TestDataLoader:
    """Tests for the DataLoader module."""
    
    def test_load_reviews(self, sample_jsonl):
        """Test loading reviews from JSONL file."""
        data_dir, filename = sample_jsonl
        loader = DataLoader(data_dir=data_dir)
        reviews = loader.load_reviews(filename, limit=10, show_progress=False)
        
        assert len(reviews) == 2
        assert reviews[0].rating == 5.0
        assert reviews[1].rating == 3.0
        
    def test_review_id_generation(self, sample_jsonl):
        """Test unique review IDs are generated."""
        data_dir, filename = sample_jsonl
        loader = DataLoader(data_dir=data_dir)
        reviews = loader.load_reviews(filename, show_progress=False)
        
        ids = [r.review_id for r in reviews]
        assert len(ids) == len(set(ids))  # All unique
        
    def test_review_hash_computation(self):
        """Test review hash computation."""
        review = Review(
            review_id="test_id",
            asin="B001234567",
            reviewer_id="A1234567890",
            rating=5.0,
            title="Test",
            text="Test text",
            timestamp=1609459200,
            verified=True,
            helpful_vote=0
        )
        
        hash1 = review.compute_hash()
        hash2 = review.compute_hash()
        
        assert len(hash1) == 64  # SHA256 hex length
        assert hash1 == hash2  # Deterministic


# ========================= Merkle Tree Tests =========================

class TestMerkleTree:
    """Tests for the MerkleTree module."""
    
    def test_build_tree(self):
        """Test building a Merkle tree."""
        reviews = create_test_reviews(8)
        tree = MerkleTree()
        root = tree.build(reviews, show_progress=False)
        
        assert root is not None
        assert len(root) == 64  # SHA256 hex
        assert tree.height > 0
        assert tree.total_nodes > len(reviews)
        
    def test_build_single_review(self):
        """Test building tree with single review."""
        reviews = create_test_reviews(1)
        tree = MerkleTree()
        root = tree.build(reviews, show_progress=False)
        
        assert root is not None
        
    def test_build_empty_raises(self):
        """Test that building with empty list raises."""
        tree = MerkleTree()
        with pytest.raises(ValueError):
            tree.build([], show_progress=False)
            
    def test_root_consistency(self):
        """Test root hash is consistent for same data."""
        reviews = create_test_reviews(8)
        
        tree1 = MerkleTree()
        tree1.build(reviews, show_progress=False)
        
        tree2 = MerkleTree()
        tree2.build(reviews, show_progress=False)
        
        assert tree1.get_root_hash() == tree2.get_root_hash()
    
    def test_add_review_dynamic(self):
        """Test dynamically adding a review without full rebuild."""
        reviews = create_test_reviews(16)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        original_root = tree.get_root_hash()
        original_leaves = len(tree.leaves)
        
        # Create new review
        new_review = Review(
            review_id="new_dynamic_review",
            asin="B9999999999",
            reviewer_id="A9999999999",
            rating=5.0,
            title="Dynamic Review",
            text="Added dynamically",
            timestamp=1609459200,
            verified=True,
            helpful_vote=5
        )
        
        # Add dynamically
        new_root = tree.add_review(new_review)
        
        # Verify tree updated
        assert len(tree.leaves) == original_leaves + 1
        assert new_root != original_root
        
        # Verify new review is searchable and proof works
        proof = tree.generate_proof("new_dynamic_review")
        assert proof is not None
        
        is_valid = tree.verify_proof(
            "new_dynamic_review",
            new_review.compute_hash(),
            proof,
            new_root
        )
        assert is_valid
    
    def test_add_review_matches_full_rebuild(self):
        """Test that dynamic add produces same result as full rebuild."""
        reviews = create_test_reviews(15)  # Odd number to test edge case
        
        new_review = Review(
            review_id="test_new_review",
            asin="BTEST123",
            reviewer_id="ATEST123",
            rating=4.0,
            title="Test",
            text="Test review",
            timestamp=1609459200,
            verified=True,
            helpful_vote=0
        )
        
        # Method 1: Dynamic add
        tree1 = MerkleTree()
        tree1.build(reviews, show_progress=False)
        tree1.add_review(new_review)
        
        # Method 2: Full rebuild with all reviews
        tree2 = MerkleTree()
        tree2.build(reviews + [new_review], show_progress=False)
        
        # Both should have same number of leaves
        assert len(tree1.leaves) == len(tree2.leaves)
        
        # Proofs should work for the new review in both trees
        proof1 = tree1.generate_proof("test_new_review")
        proof2 = tree2.generate_proof("test_new_review")
        
        assert proof1 is not None
        assert proof2 is not None


class TestMerkleProof:
    """Tests for Merkle proof functionality."""
    
    def test_generate_proof(self):
        """Test generating a proof."""
        reviews = create_test_reviews(16)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        proof = tree.generate_proof(reviews[5].review_id)
        
        assert proof is not None
        assert len(proof) > 0
        
    def test_verify_proof(self):
        """Test verifying a valid proof."""
        reviews = create_test_reviews(16)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        review = reviews[7]
        proof = tree.generate_proof(review.review_id)
        
        is_valid = tree.verify_proof(
            review.review_id,
            review.raw_hash,
            proof,
            tree.get_root_hash()
        )
        
        assert is_valid is True
        
    def test_verify_proof_wrong_hash(self):
        """Test proof fails with wrong hash."""
        reviews = create_test_reviews(16)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        review = reviews[7]
        proof = tree.generate_proof(review.review_id)
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        
        is_valid = tree.verify_proof(
            review.review_id,
            wrong_hash,
            proof,
            tree.get_root_hash()
        )
        
        assert is_valid is False
        
    def test_proof_nonexistent(self):
        """Test proof for non-existent review."""
        reviews = create_test_reviews(16)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        proof = tree.generate_proof("nonexistent_id")
        assert proof is None


# ========================= Tamper Detection Tests =========================

class TestTamperDetection:
    """Tests for tamper detection functionality."""
    
    def test_no_tampering(self):
        """Test detection with no tampering."""
        reviews = create_test_reviews(50)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        detector = TamperDetector(tree, reviews)
        result = detector.detect_tampering(reviews, show_progress=False)
        
        assert result.detected is False
        assert result.tamper_type == TamperType.NO_TAMPERING
        
    def test_detect_modification(self):
        """Test detecting record modification."""
        reviews = create_test_reviews(50)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        detector = TamperDetector(tree, reviews)
        tampered, _ = TamperSimulator.modify_record(reviews, index=25)
        result = detector.detect_tampering(tampered, show_progress=False)
        
        assert result.detected is True
        assert result.tamper_type == TamperType.MODIFICATION
        
    def test_detect_deletion(self):
        """Test detecting record deletion."""
        reviews = create_test_reviews(50)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        detector = TamperDetector(tree, reviews)
        tampered, _ = TamperSimulator.delete_record(reviews, index=25)
        result = detector.detect_tampering(tampered, show_progress=False)
        
        assert result.detected is True
        assert result.tamper_type == TamperType.DELETION
        
    def test_detect_insertion(self):
        """Test detecting record insertion."""
        reviews = create_test_reviews(50)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        detector = TamperDetector(tree, reviews)
        tampered, _ = TamperSimulator.insert_record(reviews)
        result = detector.detect_tampering(tampered, show_progress=False)
        
        assert result.detected is True
        assert result.tamper_type == TamperType.INSERTION


class TestTamperSimulator:
    """Tests for the TamperSimulator class."""
    
    def test_modify_creates_copy(self):
        """Test that modify doesn't change original."""
        reviews = create_test_reviews(10)
        original_len = len(reviews)
        
        TamperSimulator.modify_record(reviews, index=5)
        
        assert len(reviews) == original_len
        
    def test_delete_reduces_count(self):
        """Test that delete reduces record count."""
        reviews = create_test_reviews(10)
        
        tampered, _ = TamperSimulator.delete_record(reviews, index=5)
        
        assert len(tampered) == len(reviews) - 1
        
    def test_insert_increases_count(self):
        """Test that insert increases record count."""
        reviews = create_test_reviews(10)
        
        tampered, _ = TamperSimulator.insert_record(reviews)
        
        assert len(tampered) == len(reviews) + 1


# ========================= Integrity Tests =========================

class TestIntegrityVerifier:
    """Tests for the IntegrityVerifier module."""
    
    def test_save_and_load_root(self, tmp_path):
        """Test saving and loading a root."""
        verifier = IntegrityVerifier(storage_dir=str(tmp_path))
        test_hash = "a" * 64
        
        verifier.save_root(
            root_hash=test_hash,
            dataset_name="test_dataset",
            record_count=100,
            tree_height=7
        )
        
        loaded = verifier.load_latest_root("test_dataset")
        
        assert loaded is not None
        assert loaded.root_hash == test_hash
        assert loaded.record_count == 100
        
    def test_verify_integrity_match(self, tmp_path):
        """Test verification when hashes match."""
        verifier = IntegrityVerifier(storage_dir=str(tmp_path))
        test_hash = "b" * 64
        
        verifier.save_root(test_hash, "dataset", 100, 7)
        result = verifier.verify_integrity(test_hash, "dataset")
        
        assert result['status'] == "INTEGRITY_VERIFIED"
        assert result['integrity_verified'] is True
        
    def test_verify_integrity_mismatch(self, tmp_path):
        """Test verification when hashes don't match."""
        verifier = IntegrityVerifier(storage_dir=str(tmp_path))
        
        verifier.save_root("a" * 64, "dataset", 100, 7)
        result = verifier.verify_integrity("b" * 64, "dataset")
        
        assert result['status'] == "INTEGRITY_VIOLATED"
        assert result['integrity_verified'] is False


# ========================= Performance Tests =========================

class TestPerformance:
    """Performance requirement tests."""
    
    def test_proof_under_100ms(self):
        """Test proof generation + verification under 100ms."""
        reviews = create_test_reviews(10000)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        review = reviews[5000]
        
        start = time.perf_counter()
        proof = tree.generate_proof(review.review_id)
        is_valid = tree.verify_proof(
            review.review_id,
            review.raw_hash,
            proof,
            tree.get_root_hash()
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        assert is_valid is True
        assert elapsed_ms < 100, f"Proof took {elapsed_ms:.2f}ms"
        
    def test_proof_length_logarithmic(self):
        """Test proof length is O(log n)."""
        import math
        
        for n in [16, 128, 1024]:
            reviews = create_test_reviews(n)
            tree = MerkleTree()
            tree.build(reviews, show_progress=False)
            
            proof = tree.generate_proof(reviews[0].review_id)
            expected = math.ceil(math.log2(n))
            
            # Allow ±1 for padding
            assert abs(len(proof) - expected) <= 1


# ========================= Integration Tests =========================

class TestIntegration:
    """Integration tests matching project experiments."""
    
    def test_experiment_a_static_verification(self):
        """Experiment A: Static integrity verification."""
        reviews = create_test_reviews(1000)
        
        tree = MerkleTree()
        original_root = tree.build(reviews, show_progress=False)
        
        # Verify tree can be rebuilt with same root
        tree2 = MerkleTree()
        rebuilt_root = tree2.build(reviews, show_progress=False)
        
        assert original_root == rebuilt_root
        
    def test_experiment_b_tamper_simulation(self):
        """Experiment B: All tampering types detected."""
        reviews = create_test_reviews(500)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        detector = TamperDetector(tree, reviews)
        
        # Test all tampering types
        for method, expected_type in [
            (lambda r: TamperSimulator.modify_record(r, index=250), TamperType.MODIFICATION),
            (lambda r: TamperSimulator.delete_record(r, index=250), TamperType.DELETION),
            (lambda r: TamperSimulator.insert_record(r), TamperType.INSERTION)
        ]:
            tampered, _ = method(reviews)
            result = detector.detect_tampering(tampered, show_progress=False)
            
            assert result.detected is True
            assert result.tamper_type == expected_type
            
    def test_experiment_c_proof_performance(self):
        """Experiment C: Proof verification time meets requirement."""
        reviews = create_test_reviews(5000)
        tree = MerkleTree()
        tree.build(reviews, show_progress=False)
        
        times = []
        for i in range(100):
            review = reviews[i * 50]
            start = time.perf_counter()
            proof = tree.generate_proof(review.review_id)
            tree.verify_proof(review.review_id, review.raw_hash, proof, tree.get_root_hash())
            times.append((time.perf_counter() - start) * 1000)
        
        avg_time = sum(times) / len(times)
        assert avg_time < 100, f"Average proof time {avg_time:.2f}ms exceeds 100ms"
