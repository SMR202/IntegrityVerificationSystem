"""
Data Preprocessing Module
Handles loading, parsing, and normalizing Amazon review datasets.
"""

import json
import os
import hashlib
from typing import Generator, Dict, List, Optional, Any
from tqdm import tqdm


class Review:
    """Represents a single Amazon review with all relevant fields."""
    
    __slots__ = ['review_id', 'asin', 'reviewer_id', 'rating', 'title', 
                 'text', 'timestamp', 'verified', 'helpful_vote', 'raw_hash']
    
    def __init__(self, 
                 review_id: str,
                 asin: str,
                 reviewer_id: str,
                 rating: float,
                 title: str,
                 text: str,
                 timestamp: int,
                 verified: bool = False,
                 helpful_vote: int = 0):
        self.review_id = review_id
        self.asin = asin  # Product ID
        self.reviewer_id = reviewer_id
        self.rating = rating
        self.title = title
        self.text = text
        self.timestamp = timestamp
        self.verified = verified
        self.helpful_vote = helpful_vote
        self.raw_hash = None  # Will be computed during tree construction
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert review to dictionary."""
        return {
            'review_id': self.review_id,
            'asin': self.asin,
            'reviewer_id': self.reviewer_id,
            'rating': self.rating,
            'title': self.title,
            'text': self.text,
            'timestamp': self.timestamp,
            'verified': self.verified,
            'helpful_vote': self.helpful_vote
        }
    
    def to_canonical_string(self) -> str:
        """
        Convert review to a canonical string representation for hashing.
        This ensures consistent hashing regardless of field order.
        """
        return (f"{self.review_id}|{self.asin}|{self.reviewer_id}|"
                f"{self.rating}|{self.title}|{self.text}|"
                f"{self.timestamp}|{self.verified}|{self.helpful_vote}")
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the review."""
        canonical = self.to_canonical_string()
        self.raw_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        return self.raw_hash
    
    def __repr__(self) -> str:
        return f"Review(id={self.review_id}, asin={self.asin}, rating={self.rating})"


class DataLoader:
    """
    Handles loading and preprocessing of Amazon review datasets.
    Supports streaming for memory-efficient processing of large files.
    """
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.loaded_reviews: List[Review] = []
        self.review_index: Dict[str, int] = {}  # review_id -> index in loaded_reviews
        self.product_index: Dict[str, List[int]] = {}  # asin -> list of indices
        
    def _generate_review_id(self, record: Dict, index: int) -> str:
        """
        Generate a unique review ID if not present in the record.
        Uses combination of reviewer_id, asin, and timestamp for uniqueness.
        """
        reviewer_id = record.get('reviewerID', '')
        asin = record.get('asin', '')
        timestamp = record.get('unixReviewTime', index)
        
        # Create a hash-based ID from the combination
        unique_str = f"{reviewer_id}_{asin}_{timestamp}"
        short_hash = hashlib.md5(unique_str.encode()).hexdigest()[:12]
        return f"R{short_hash.upper()}"
    
    def _parse_record(self, record: Dict, index: int) -> Review:
        """Parse a JSON record into a Review object."""
        review_id = self._generate_review_id(record, index)
        
        return Review(
            review_id=review_id,
            asin=record.get('asin', ''),
            reviewer_id=record.get('reviewerID', ''),
            rating=float(record.get('overall', 0.0)),
            title=record.get('summary', ''),
            text=record.get('reviewText', ''),
            timestamp=int(record.get('unixReviewTime', 0)),
            verified=bool(record.get('verified', False)),
            helpful_vote=int(record.get('helpful_vote', 0))
        )
    
    def stream_reviews(self, filename: str, limit: Optional[int] = None) -> Generator[Review, None, None]:
        """
        Stream reviews from a file without loading all into memory.
        Useful for initial processing or when memory is constrained.
        
        Args:
            filename: Name of the JSON/JSONL file in data directory
            limit: Maximum number of reviews to stream (None for all)
            
        Yields:
            Review objects one at a time
        """
        filepath = os.path.join(self.data_dir, filename)
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset file not found: {filepath}")
        
        count = 0
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if limit and count >= limit:
                    break
                try:
                    record = json.loads(line.strip())
                    review = self._parse_record(record, count)
                    count += 1
                    yield review
                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping malformed JSON at line {count}: {e}")
                    continue
    
    def load_reviews(self, filename: str, limit: Optional[int] = None, 
                     show_progress: bool = True) -> List[Review]:
        """
        Load reviews from file into memory.
        
        Args:
            filename: Name of the JSON/JSONL file in data directory
            limit: Maximum number of reviews to load (None for all)
            show_progress: Whether to show progress bar
            
        Returns:
            List of Review objects
        """
        filepath = os.path.join(self.data_dir, filename)
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset file not found: {filepath}")
        
        # Count total lines for progress bar
        total_lines = None
        if show_progress:
            print("Counting records...")
            with open(filepath, 'r', encoding='utf-8') as f:
                total_lines = sum(1 for _ in f)
            if limit:
                total_lines = min(total_lines, limit)
        
        self.loaded_reviews = []
        self.review_index = {}
        self.product_index = {}
        
        iterator = self.stream_reviews(filename, limit)
        if show_progress:
            iterator = tqdm(iterator, total=total_lines, desc="Loading reviews")
        
        for idx, review in enumerate(iterator):
            self.loaded_reviews.append(review)
            
            # Build review index
            self.review_index[review.review_id] = idx
            
            # Build product index
            if review.asin not in self.product_index:
                self.product_index[review.asin] = []
            self.product_index[review.asin].append(idx)
        
        print(f"\nLoaded {len(self.loaded_reviews):,} reviews")
        print(f"Unique products: {len(self.product_index):,}")
        
        return self.loaded_reviews
    
    def get_review_by_id(self, review_id: str) -> Optional[Review]:
        """Get a review by its ID."""
        idx = self.review_index.get(review_id)
        if idx is not None:
            return self.loaded_reviews[idx]
        return None
    
    def get_reviews_by_product(self, asin: str) -> List[Review]:
        """Get all reviews for a product."""
        indices = self.product_index.get(asin, [])
        return [self.loaded_reviews[i] for i in indices]
    
    def get_review_by_index(self, index: int) -> Optional[Review]:
        """Get a review by its index position."""
        if 0 <= index < len(self.loaded_reviews):
            return self.loaded_reviews[index]
        return None
    
    def get_dataset_stats(self) -> Dict[str, Any]:
        """Get statistics about the loaded dataset."""
        if not self.loaded_reviews:
            return {"error": "No reviews loaded"}
        
        ratings = [r.rating for r in self.loaded_reviews]
        verified_count = sum(1 for r in self.loaded_reviews if r.verified)
        
        return {
            "total_reviews": len(self.loaded_reviews),
            "unique_products": len(self.product_index),
            "unique_reviewers": len(set(r.reviewer_id for r in self.loaded_reviews)),
            "average_rating": sum(ratings) / len(ratings),
            "verified_purchases": verified_count,
            "verified_percentage": (verified_count / len(self.loaded_reviews)) * 100
        }
    
    def get_sample_reviews(self, n: int = 10) -> List[Review]:
        """Get first n reviews for display purposes."""
        return self.loaded_reviews[:n]


def count_records(filepath: str) -> int:
    """Count total records in a JSONL file."""
    count = 0
    with open(filepath, 'r', encoding='utf-8') as f:
        for _ in f:
            count += 1
    return count


# Quick test
if __name__ == "__main__":
    loader = DataLoader()
    
    # Test with a small sample first
    print("Testing data loader with 100 reviews...")
    reviews = loader.load_reviews("Video_Games.json", limit=100)
    
    print("\nDataset Statistics:")
    stats = loader.get_dataset_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\nSample Review:")
    if reviews:
        sample = reviews[0]
        print(f"  ID: {sample.review_id}")
        print(f"  Product: {sample.asin}")
        print(f"  Rating: {sample.rating}")
        print(f"  Title: {sample.title[:50]}...")
        print(f"  Hash: {sample.compute_hash()[:32]}...")
