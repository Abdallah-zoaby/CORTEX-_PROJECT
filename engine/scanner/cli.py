
import argparse
import asyncio
import os
import glob
from .main import TitaniumScannerV15
from .server import WebInterface
from .data.types import ScanConfig, ScanMode

def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(description='Titanium Web Scanner v15.0')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('--mode', choices=['safe', 'destructive', 'stealth', 'comprehensive'],
                       default='safe', help='Scanning mode')
    parser.add_argument('--depth', type=int, default=5, help='Maximum crawl depth')
    parser.add_argument('--concurrency', type=int, default=25, help='Maximum concurrent requests')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--output', choices=['json', 'html', 'pdf', 'csv'],
                       default='html', help='Output format')
    parser.add_argument('--web', action='store_true', help='Start web interface')
    parser.add_argument('--port', type=int, default=8080, help='Web interface port')
    
    args = parser.parse_args()
    
    if args.web:
        # Start web interface
        config = ScanConfig(target_url=args.target or "http://localhost")
        scanner = TitaniumScannerV15(config)
        interface = WebInterface(scanner)
        interface.run(port=args.port)
    elif args.target:
        # Run command-line scan
        config = ScanConfig(
            target_url=args.target,
            mode=ScanMode(args.mode),
            max_depth=args.depth,
            max_concurrency=args.concurrency,
            timeout=args.timeout,
        )
        
        scanner = TitaniumScannerV15(config)
        
        # Run scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(scanner.scan())
            
            # Generate report
            report = scanner.report_generator.generate(result, format=args.output)
            
            if args.output == 'json':
                print(report)
            else:
                filename = f"report_{scanner.scan_id}.{args.output}"
                with open(filename, 'wb' if args.output == 'pdf' else 'w') as f:
                    f.write(report if args.output != 'pdf' else report)
                print(f"✅ Report saved to {filename}")
                
        except KeyboardInterrupt:
            print("\n⚠️ Scan interrupted by user")
        except Exception as e:
            print(f"❌ Scan failed: {e}")
        finally:
            loop.close()
    else:
        parser.print_help()

if __name__ == "__main__":
    # Clean old files
    for pattern in ["report_*.html", "report_*.json", "report_*.pdf", "report_*.csv"]:
        for file in glob.glob(pattern):
            try:
                os.remove(file)
                print(f"🗑️ Cleaned: {file}")
            except:
                pass
    
    # Run scanner
    main()
