#!/usr/bin/env python3
"""
AWS No-Parameter Operations Scanner
Discovers AWS API operations that don't require any parameters
"""

import boto3
import botocore.exceptions
import json
import argparse
import sys
import time
import signal
import shutil
from contextlib import contextmanager

# List of problematic services that need special timeout handling
PROBLEMATIC_SERVICES = [
    'cloudhsm', 'cloudhsmv2', 'iotfleetwise', 'iotroborunner',
    'lookoutequipment', 'lookoutvision', 'braket', 'appflow',
    'codeartifact', 'appsync', 'medialive', 'timestream'
]

@contextmanager
def timeout(seconds):
    """Context manager for timing out function calls"""
    def signal_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    # Set the timeout handler
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Cancel the alarm after the operation
        signal.alarm(0)


class ProgressBar:
    """Progress bar for tracking scanning progress"""
    
    def __init__(self, total, width=50):
        self.total = total
        self.width = width
        self.current = 0
        self.start_time = time.time()
        self.last_service = ""
        self.api_current = 0
        self.api_total = 0
        
        # Get terminal width
        try:
            self.term_width = shutil.get_terminal_size().columns
        except:
            self.term_width = 100
    
    def update(self, current, service, api_current=0, api_total=0):
        """Update the progress bar
        
        Args:
            current: Current service number
            service: Current service being processed
            api_current: Current API operation number
            api_total: Total API operations for this service
        """
        self.current = current
        self.last_service = service
        self.api_current = api_current
        self.api_total = api_total
        
        # First, clear the entire line
        print("\r" + " " * self.term_width, end="\r", flush=True)
        
        # Calculate progress percentage
        percent = int(100 * (current / self.total))
        
        # Calculate how many progress bar segments to fill
        filled_width = int(self.width * current / self.total)
        bar = '👾' * filled_width + '.' * (self.width - filled_width)
        
        # Add ANSI color codes for yellow
        #yellow = "\033[93m"
        #reset = "\033[0m"
        
        # Create fixed-width progress string
        if api_total > 0:
            progress_str = f"[{current}/{self.total}][{bar}] {percent}% [{service[:15]} - API: {api_current}/{api_total}]"
        else:
            progress_str = f"[{current}/{self.total}][{bar}] {percent}% [{service[:15]}]"
        
        # Ensure it doesn't exceed terminal width
        if len(progress_str) > self.term_width - 2:
            progress_str = progress_str[:self.term_width - 5] + "..."
        
        # Print the progress bar
        print(f"\r{progress_str}", end="", flush=True)
    
    def update_api(self, current, total):
        """Update just the API progress counter
        
        Args:
            current: Current API operation number
            total: Total API operations
        """
        self.update(self.current, self.last_service, current, total)


class AWSOperationScanner:
    """Scans AWS services for operations that don't require parameters"""
    
    def __init__(self, profile_name=None):
        """Initialize with AWS credentials
        
        Args:
            profile_name: AWS profile name from ~/.aws/credentials
        """
        # Create session with profile if specified
        session_kwargs = {}
        if profile_name:
            session_kwargs['profile_name'] = profile_name
            
        self.session = boto3.Session(**session_kwargs)
        self.results = {}
        self.verbose = False
        self.successful_ops_count = {}
        
        # Function to be assigned for progress tracking
        self.progress_callback = lambda x, y: None
    
    def log(self, message):
        """Print message if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def get_client_for_service(self, service):
        """Get appropriate client for a service with handling for problematic services
        
        Args:
            service: AWS service name
            
        Returns:
            boto3 client for the service
        """
        if service in PROBLEMATIC_SERVICES:
            # Use short timeouts for problematic services
            return self.session.client(
                service,
                config=boto3.config.Config(
                    connect_timeout=3,
                    read_timeout=3
                )
            )
        else:
            # Normal client for other services
            return self.session.client(service)
    
    def test_operation(self, service, operation, client):
        """Test if an API operation works without parameters
        
        Args:
            service: Service name
            operation: Operation name
            client: Boto3 client for the service
            
        Returns:
            Boolean indicating if it works without parameters
        """
        try:
            # Get the method
            method = getattr(client, operation)
            
            # Apply timeout only for problematic services
            if service in PROBLEMATIC_SERVICES:
                # Call with timeout for problematic services
                with timeout(5):
                    method()
            else:
                # Normal call for regular services
                method()
            
            # If we get here, it worked without parameters
            return True
            
        except TimeoutError:
            # Timed out, skip this operation
            return False
            
        except botocore.exceptions.ParamValidationError:
            # This means parameters were required
            return False
            
        except botocore.exceptions.ClientError as e:
            # Check if this is a permissions issue (which means the API call syntax was valid)
            error = e.response.get('Error', {})
            error_code = error.get('Code', '')
            
            # These error codes usually mean the API call was valid but access denied
            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException',
                              'ExpiredToken', 'InvalidClientTokenId']:
                return True
                
            # Other client errors might be due to missing parameters
            return False
            
        except Exception as e:
            # Check if this is a no-such-method error, which is common for non-API methods
            if "has no attribute" in str(e):
                return False
                
            # Check if this is an endpoint discovery error, which usually means the call syntax is valid
            if "Could not connect to the endpoint URL" in str(e):
                return True
                
            # Any other exception means it probably didn't work
            self.log(f"    Error testing {service}.{operation}: {str(e)}")
            return False
    
    def discover_service_operations(self, service, progress_callback=None):
        """Discover operations that don't require parameters for a service
        
        Args:
            service: AWS service name
            progress_callback: Function to call to update progress
            
        Returns:
            List of operations that don't require parameters
        """
        no_param_operations = []
        
        try:
            # Get client for this service with appropriate config
            client = self.get_client_for_service(service)
            
            # Get all operations by inspecting client methods
            operations = []
            excluded_methods = ['close', 'generate_presigned_url', 'get_available_subresources', 'meta']
            for attr_name in dir(client):
                if callable(getattr(client, attr_name)) and not attr_name.startswith('_'):
                    if not attr_name.startswith(('get_waiter', 'get_paginator', 'can_paginate')) and attr_name not in excluded_methods:
                        operations.append(attr_name)
            
            # Prioritize list/describe operations
            list_ops = [op for op in operations if op.startswith(('list_', 'describe_'))]
            other_ops = [op for op in operations if not op.startswith(('list_', 'describe_'))]
            sorted_operations = list_ops + other_ops
            
            # Get total operations count for progress display
            total_ops = len(sorted_operations)
            
            # Initialize progress
            if progress_callback:
                progress_callback(0, total_ops)
            
            # Test each operation
            for i, op in enumerate(sorted_operations, 1):
                # Update progress
                if progress_callback:
                    progress_callback(i, total_ops)
                    
                # Test the operation
                if self.test_operation(service, op, client):
                    # If successful, add to list (convert to kebab-case for CLI)
                    cli_op = op.replace('_', '-')
                    no_param_operations.append(cli_op)
                    self.log(f"  ✓ {cli_op}")
                else:
                    self.log(f"  ✗ {op} (requires parameters)")
                    
        except Exception as e:
            self.log(f"Error scanning {service}: {str(e)}")
        
        return no_param_operations
    
    def scan_services(self, services, output_file='aws_operations.json'):
        """Scan multiple services for operations without parameters
        
        Args:
            services: List of service names to scan
            output_file: Path to save results JSON
        
        Returns:
            Dict mapping services to their no-param operations
        """
        # Count total services for progress reporting
        service_count = len(services)
        
        # Initialize progress bar
        progress = ProgressBar(service_count)
        
        # Scan each service
        for i, service in enumerate(services, 1):
            # Update main progress bar
            progress.update(i, service)
            
            # Show special note for problematic services
            if service in PROBLEMATIC_SERVICES:
                self.log(f"⚠️ {service} is a known problematic service, using special handling")
            
            # Function to update API progress
            def update_api_progress(current, total):
                progress.update_api(current, total)
            
            # Get operations for this service
            operations = self.discover_service_operations(service, update_api_progress)
            
            # Add to results if any operations found
            if operations:
                self.results[service] = operations
                self.successful_ops_count[service] = len(operations)
            
            # Save results periodically (every 10 services)
            if i % 10 == 0 or service in PROBLEMATIC_SERVICES:
                with open(output_file, 'w') as f:
                    json.dump(self.results, f, indent=2)
                self.log(f"Saved partial results to {output_file}")
            
            # Small delay to avoid rate limiting
            time.sleep(0.5)
        
        # Save final results
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        return self.results
    
    def show_summary(self, output_file):
        """Show summary of results
        
        Args:
            output_file: Path to the saved results file
        """
        # Get statistics
        total_services = len(self.results)
        total_operations = sum(len(ops) for ops in self.results.values())
        
        print(f"\nResults saved to {output_file}")
        print(f"Found {total_operations} operations across {total_services} services")
        
        # Print services with the most operations
        if self.successful_ops_count:
            print("\nTop services with most operations:")
            top_services = sorted(self.successful_ops_count.items(), key=lambda x: x[1], reverse=True)[:5]
            for service, count in top_services:
                print(f"  {service}: {count} operations")
            
        # Print some examples
        if self.results:
            print("\nExample operations (small sample):")
            count = 0
            for service, operations in sorted(self.results.items(), key=lambda x: len(x[1]), reverse=True):
                if operations:
                    example_ops = operations[:3]  # Show up to 3 operations per service
                    print(f"  {service}: {', '.join(example_ops)}")
                    count += 1
                    if count >= 5:  # Show max 5 services
                        break


def load_services_from_file(filename):
    """Load service names from a file
    
    Args:
        filename: Path to file containing service names
        
    Returns:
        List of service names
    """
    try:
        with open(filename, 'r') as f:
            services = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(services)} services from {filename}")
        return services
    except Exception as e:
        print(f"Error loading services file: {str(e)}")
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='AWS No-Parameter Operations Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan default services with default profile
  python aws_api_pull.py run
  
  # Scan services from a file with a specific profile
  python aws_api_pull.py run --profile myprofile --services-file services.txt
  
  # Scan with verbose output and custom output file
  python aws_api_pull.py run --verbose --output my_results.json
  
Notes:
  - The script will scan AWS services and find API operations that don't require parameters
  - Results are saved as a JSON file mapping services to their no-parameter operations
  - For problematic services like CloudHSM, special timeout handling is applied
  - The script handles both access denied errors and parameter validation errors
  '''
    )
    
    parser.add_argument('action', nargs='?', help='Use "run" to execute the scan')
    parser.add_argument('--profile', type=str, help='AWS profile name from ~/.aws/credentials')
    parser.add_argument('--services-file', type=str, help='File with AWS service names, one per line')
    parser.add_argument('--output', type=str, default='aws_operations.json', 
                      help='Output JSON file (default: aws_operations.json)')
    parser.add_argument('--verbose', action='store_true', 
                      help='Show detailed output, including all operation tests')
    
    args = parser.parse_args()
    
    # Show help by default if "run" is not specified
    if args.action != 'run':
        parser.print_help()
        return
    
    # Initialize scanner
    scanner = AWSOperationScanner(profile_name=args.profile)
    scanner.verbose = args.verbose
    
    # Get services to scan
    if args.services_file:
        services = load_services_from_file(args.services_file)
    else:
        # Use a few common services for testing
        services = ['iam', 's3', 'ec2', 'rds', 'lambda']
        print(f"Using default services: {', '.join(services)}")
    
    # Run scan
    scanner.scan_services(services, args.output)
    
    # Show summary
    scanner.show_summary(args.output)


if __name__ == "__main__":
    main()