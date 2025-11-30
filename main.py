#!/usr/bin/env python
"""
Merkle Tree Integrity Verification System
Main entry point for the application.

Usage:
    python main.py          # Launch CLI interface
    python main.py --gui    # Launch GUI interface (if available)
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Merkle Tree Integrity Verification System for Amazon Reviews"
    )
    parser.add_argument(
        '--gui', 
        action='store_true',
        help='Launch the graphical user interface'
    )
    parser.add_argument(
        '--benchmark',
        type=int,
        metavar='N',
        help='Run benchmark with N records and exit'
    )
    
    args = parser.parse_args()
    
    if args.gui:
        try:
            from src.gui import run_gui
            run_gui()
        except ImportError as e:
            print(f"GUI not available: {e}")
            print("Falling back to CLI...")
            from src.cli import main as cli_main
            cli_main()
    elif args.benchmark:
        from src.data_loader import DataLoader
        from src.performance import PerformanceMonitor
        
        print(f"Running benchmark with {args.benchmark:,} records...")
        loader = DataLoader()
        reviews = loader.load_reviews("Video_Games.json", limit=args.benchmark)
        
        monitor = PerformanceMonitor()
        metrics = monitor.run_full_benchmark("Video_Games", reviews)
        monitor.save_metrics(metrics)
    else:
        from src.cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    main()
