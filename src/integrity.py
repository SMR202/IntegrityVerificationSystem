"""
Integrity Verification Module
Handles storing, loading, and comparing Merkle roots for data integrity verification.
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict


@dataclass
class RootRecord:
    """Represents a stored Merkle root with metadata."""
    root_hash: str
    dataset_name: str
    record_count: int
    created_at: str
    tree_height: int
    hash_algorithm: str = "SHA-256"
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RootRecord':
        return cls(**data)


class IntegrityVerifier:
    """
    Manages Merkle root storage and integrity verification.
    
    Features:
    - Save and load Merkle roots to/from files
    - Compare current root against stored root
    - Maintain history of roots for versioning
    - Generate integrity reports
    """
    
    def __init__(self, storage_dir: str = "roots"):
        self.storage_dir = storage_dir
        self.current_root: Optional[RootRecord] = None
        self.root_history: List[RootRecord] = []
        
        # Create storage directory if it doesn't exist
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
    
    def _get_storage_path(self, dataset_name: str) -> str:
        """Get the file path for a dataset's root storage."""
        safe_name = dataset_name.replace(" ", "_").replace("/", "_")
        return os.path.join(self.storage_dir, f"{safe_name}_roots.json")
    
    def save_root(self, root_hash: str, dataset_name: str, 
                  record_count: int, tree_height: int, 
                  notes: str = "") -> RootRecord:
        """
        Save a Merkle root to persistent storage.
        
        Args:
            root_hash: The Merkle root hash
            dataset_name: Name of the dataset
            record_count: Number of records in the dataset
            tree_height: Height of the Merkle tree
            notes: Optional notes about this root
            
        Returns:
            The created RootRecord
        """
        record = RootRecord(
            root_hash=root_hash,
            dataset_name=dataset_name,
            record_count=record_count,
            created_at=datetime.now().isoformat(),
            tree_height=tree_height,
            notes=notes
        )
        
        # Load existing history
        storage_path = self._get_storage_path(dataset_name)
        history = self._load_history(storage_path)
        
        # Add new record
        history.append(record.to_dict())
        
        # Save to file
        with open(storage_path, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
        
        self.current_root = record
        self.root_history = [RootRecord.from_dict(r) for r in history]
        
        print(f"[OK] Root saved successfully!")
        print(f"  Hash: {root_hash[:32]}...")
        print(f"  Stored at: {storage_path}")
        
        return record
    
    def _load_history(self, storage_path: str) -> List[Dict]:
        """Load root history from file."""
        if os.path.exists(storage_path):
            with open(storage_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    
    def load_latest_root(self, dataset_name: str) -> Optional[RootRecord]:
        """
        Load the most recent root for a dataset.
        
        Args:
            dataset_name: Name of the dataset
            
        Returns:
            The latest RootRecord or None if not found
        """
        storage_path = self._get_storage_path(dataset_name)
        history = self._load_history(storage_path)
        
        if history:
            self.root_history = [RootRecord.from_dict(r) for r in history]
            self.current_root = self.root_history[-1]
            return self.current_root
        
        return None
    
    def load_all_roots(self, dataset_name: str) -> List[RootRecord]:
        """Load all stored roots for a dataset."""
        storage_path = self._get_storage_path(dataset_name)
        history = self._load_history(storage_path)
        self.root_history = [RootRecord.from_dict(r) for r in history]
        return self.root_history
    
    def compare_roots(self, current_hash: str, 
                      stored_record: Optional[RootRecord] = None) -> Dict[str, Any]:
        """
        Compare a current root hash against a stored root.
        
        Args:
            current_hash: The current Merkle root hash
            stored_record: The stored root to compare against (uses latest if None)
            
        Returns:
            Dictionary with comparison results
        """
        if stored_record is None:
            stored_record = self.current_root
        
        if stored_record is None:
            return {
                "status": "NO_STORED_ROOT",
                "message": "No stored root found for comparison",
                "integrity_verified": None
            }
        
        is_match = current_hash == stored_record.root_hash
        
        return {
            "status": "INTEGRITY_VERIFIED" if is_match else "INTEGRITY_VIOLATED",
            "message": "Data integrity verified - roots match" if is_match 
                      else "DATA TAMPERING DETECTED - roots do not match",
            "integrity_verified": is_match,
            "current_hash": current_hash,
            "stored_hash": stored_record.root_hash,
            "stored_at": stored_record.created_at,
            "record_count": stored_record.record_count
        }
    
    def verify_integrity(self, current_hash: str, 
                         dataset_name: str) -> Dict[str, Any]:
        """
        Verify data integrity against stored root.
        
        Args:
            current_hash: Current Merkle root hash
            dataset_name: Name of the dataset
            
        Returns:
            Verification result dictionary
        """
        # Load the latest stored root
        stored = self.load_latest_root(dataset_name)
        
        if stored is None:
            return {
                "status": "NO_BASELINE",
                "message": f"No stored root found for dataset '{dataset_name}'. "
                          "Save current root to establish baseline.",
                "integrity_verified": None,
                "current_hash": current_hash
            }
        
        return self.compare_roots(current_hash, stored)
    
    def get_root_history(self, dataset_name: str) -> List[Dict[str, Any]]:
        """Get the history of all roots for a dataset."""
        roots = self.load_all_roots(dataset_name)
        return [r.to_dict() for r in roots]
    
    def delete_root_history(self, dataset_name: str) -> bool:
        """Delete all stored roots for a dataset."""
        storage_path = self._get_storage_path(dataset_name)
        if os.path.exists(storage_path):
            os.remove(storage_path)
            self.current_root = None
            self.root_history = []
            return True
        return False
    
    def generate_integrity_report(self, current_hash: str, 
                                  dataset_name: str) -> str:
        """Generate a detailed integrity report."""
        result = self.verify_integrity(current_hash, dataset_name)
        
        lines = []
        lines.append("=" * 60)
        lines.append("INTEGRITY VERIFICATION REPORT")
        lines.append("=" * 60)
        lines.append(f"Dataset: {dataset_name}")
        lines.append(f"Report Time: {datetime.now().isoformat()}")
        lines.append("")
        lines.append(f"Status: {result['status']}")
        lines.append(f"Message: {result['message']}")
        lines.append("")
        lines.append(f"Current Root Hash:")
        lines.append(f"  {result.get('current_hash', 'N/A')}")
        
        if result.get('stored_hash'):
            lines.append(f"\nStored Root Hash:")
            lines.append(f"  {result['stored_hash']}")
            lines.append(f"\nStored At: {result.get('stored_at', 'N/A')}")
            lines.append(f"Record Count: {result.get('record_count', 'N/A')}")
        
        # Add history summary
        if self.root_history:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"ROOT HISTORY ({len(self.root_history)} records)")
            lines.append("=" * 60)
            for i, record in enumerate(self.root_history[-5:], 1):  # Last 5
                lines.append(f"\n[{i}] {record.created_at}")
                lines.append(f"    Hash: {record.root_hash[:32]}...")
                lines.append(f"    Records: {record.record_count:,}")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)


# Quick test
if __name__ == "__main__":
    print("Testing Integrity Verifier...\n")
    
    verifier = IntegrityVerifier()
    
    # Simulate a root hash
    test_hash = "fdc25f2e278b02cd1466340939a44fa10fdddbf06e4aa15ba20e9c174c19844c"
    dataset = "Video_Games"
    
    # Save root
    print("1. Saving root...")
    verifier.save_root(
        root_hash=test_hash,
        dataset_name=dataset,
        record_count=1000,
        tree_height=10,
        notes="Initial test"
    )
    
    # Verify with same hash
    print("\n2. Verifying with same hash...")
    result = verifier.verify_integrity(test_hash, dataset)
    print(f"   Status: {result['status']}")
    print(f"   Integrity Verified: {result['integrity_verified']}")
    
    # Verify with different hash (simulating tampering)
    print("\n3. Verifying with different hash (tampered)...")
    tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    result = verifier.verify_integrity(tampered_hash, dataset)
    print(f"   Status: {result['status']}")
    print(f"   Integrity Verified: {result['integrity_verified']}")
    
    # Generate report
    print("\n4. Generating integrity report...")
    report = verifier.generate_integrity_report(test_hash, dataset)
    print(report)
