#!/usr/bin/env python3
import boto3
import botocore.exceptions
import argparse, re, sys, json, time, shutil
from concurrent.futures import ThreadPoolExecutor

# Try to import tqdm for progress bars
# try:
#     from tqdm import tqdm
#     TQDM_AVAILABLE = True
# except ImportError:
#     TQDM_AVAILABLE = False
#     print("For better progress bars, install tqdm: pip install tqdm")

# Try to import rich for colored output
try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# In the Permission Scanner script, add a ProgressBar class similar to the API puller
class ProgressBar:
    def __init__(self, total, width=50):
        self.total = total
        self.width = width
        self.current = 0
        self.service = ""
        self.api_current = 0
        self.api_total = 0
        
        # Get terminal width
        try:
            self.term_width = shutil.get_terminal_size().columns
        except:
            self.term_width = 100
    
    def update(self, current, service, api_current=0, api_total=0):
        self.current = current
        self.service = service
        self.api_current = api_current
        self.api_total = api_total
        
        # Calculate progress percentage
        percent = int(100 * (current / self.total))
        
        # Calculate how many progress bar segments to fill
        filled_width = int(self.width * current / self.total)
        bar = '👾' * filled_width + '.' * (self.width - filled_width)
        
        # Create the progress string with API progress
        yellow = "\033[93m"
        reset = "\033[0m"
        
        # First, clear the entire line
        print("\r" + " " * self.term_width, end="\r", flush=True)
        
        if api_total > 0:
            progress_str = f"[{current}/{self.total}][{bar}] {percent}% [service: {yellow}{service}{reset} - API: {api_current}/{api_total}]"
        else:
            progress_str = f"[{current}/{self.total}][{bar}] {percent}% [service: {yellow}{service}{reset}]"
        
        # Truncate if too long for terminal
        if len(progress_str) > self.term_width - 5:
            service_display = service[:10] + "..."
            if api_total > 0:
                progress_str = f"[{current}/{self.total}][{bar}] {percent}% [svc: {yellow}{service_display}{reset} - API: {api_current}/{api_total}]"
            else:
                progress_str = f"[{current}/{self.total}][{bar}] {percent}% [svc: {yellow}{service_display}{reset}]"
            
            # Still truncate if necessary
            if len(progress_str) > self.term_width - 5:
                progress_str = progress_str[:self.term_width - 5] + "..."
        
        # Print the progress bar
        print(f"\r{progress_str}", end="", flush=True)
    
    def update_api(self, current, total):
        self.update(self.current, self.service, current, total)

class AWSSdkPermissionScanner:
    """Scans AWS permissions across multiple services using AWS SDK"""

    def __init__(self, profile_name=None, region_name=None):
        """Initialize scanner with AWS credentials"""
        # Create session with profile if specified
        session_kwargs = {}
        if profile_name:
            session_kwargs['profile_name'] = profile_name
        if region_name:
            session_kwargs['region_name'] = region_name
            
        self.session = boto3.Session(**session_kwargs)
        self.results = {}

        # Function to be assigned for progress tracking
        self.progress_callback = lambda x, y: None
        
    def _extract_arn_from_error(self, error_message):
        """Extract ARN from AWS error message"""
        if not error_message:
            return None
            
        # Try to match IAM ARNs (user, role, policy, group)
        arn_match = re.search(r'arn:aws:iam::[0-9]+:(user|role|policy|group)/[^\s:]+', error_message)
        if arn_match:
            return arn_match.group(0)
            
        # Try to match any AWS ARN as a fallback
        any_arn_match = re.search(r'arn:aws:[^:]+:[^:]*:[0-9]+:[^\s:]+', error_message)
        if any_arn_match:
            return any_arn_match.group(0)
            
        return None

    def test_operation(self, service, operation):
        """Test if a specific AWS API operation is allowed"""
        try:
            # Try to create the client (this can fail for some services)
            client = self.session.client(service)
            
            # Check if operation exists
            if not hasattr(client, operation):
                return {
                    'status': 'error',
                    'message': f"Operation {operation} not found in {service}"
                }
            
            # Call the API operation
            method = getattr(client, operation)
            response = method()
            
            # Successfully called the API
            return {
                'status': 'success',
                'message': "Access allowed",
                'response': response
            }
            
        except botocore.exceptions.ClientError as e:
            error_message = str(e)
            
            # Check if this is an access denied error
            if "AccessDenied" in error_message or "UnauthorizedOperation" in error_message:
                arn = self._extract_arn_from_error(error_message)
                if arn:
                    return {
                        'status': 'denied',
                        'message': f"Access denied: {arn}"
                    }
                else:
                    return {
                        'status': 'denied',
                        'message': "Access denied"
                    }
            else:
                # Other client errors (e.g., InvalidParameterValue)
                return {
                    'status': 'error',
                    'message': str(e)
                }
                
        except Exception as e:
            # Other exceptions (e.g., EndpointConnectionError)
            return {
                'status': 'error',
                'message': str(e)
            }

    def scan_service_operations(self, service, operations, max_workers=5):
        """Scan multiple operations for a service"""
        results = {}
        
        # Skip empty operations list
        if not operations:
            return results
        
        total_ops = len(operations)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_op = {
                executor.submit(self.test_operation, service, op): op 
                for op in operations
            }
            
            # Process results as they complete
            for future in future_to_op:
                operation = future_to_op[future]
                try:
                    results[operation] = future.result()
                except Exception as e:
                    results[operation] = {
                        'status': 'error',
                        'message': f"Execution error: {str(e)}"
                    }
                
                # Update progress for API operations
                completed += 1
                self.progress_callback(completed, total_ops)
        
        return results
    
    def check_credentials(self):
        """Check if credentials are valid and if using a role or IAM user"""
        try:
            # Get caller identity to check credentials
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            
            # Check if using a role or IAM user
            arn = identity.get('Arn', '')
            is_role = ':assumed-role/' in arn or ':role/' in arn
            
            # Credentials are valid
            if is_role:
                return True, True, "Using role credentials"
            else:
                return True, False, "Using IAM user credentials"
                
        except botocore.exceptions.ClientError as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            error_message = str(e)
            
            if error_code == 'ExpiredToken':
                return False, False, "AWS session token has expired"
            elif 'InvalidClientTokenId' in error_message:
                return False, False, "Invalid AWS credentials"
            elif 'AccessDenied' in error_message:
                return False, False, "Access denied - check your permissions"
            else:
                return False, False, f"Credential error: {error_code} - {error_message}"
        except Exception as e:
            return False, False, f"Error checking credentials: {str(e)}"

    def scan_services(self, services_to_check):
        """Scan multiple AWS services"""
        results = {}
        unique_arns = set()  # Track unique ARNs found in errors
        
        total_services = len(services_to_check)
        
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"Scanning [bold cyan]{total_services}[/bold cyan] AWS services for permissions...")
            
            # Check credentials and print info
            is_valid, is_role, cred_message = self.check_credentials()
            if is_valid:
                if is_role:
                    console.print(f"[green]✓[/green] {cred_message}")
                else:
                    console.print(f"[yellow]![/yellow] {cred_message}")
            else:
                console.print(f"[red]✗[/red] {cred_message}")
        else:
            print(f"Scanning {total_services} AWS services for permissions...")
            
            # Check credentials and print info
            is_valid, is_role, cred_message = self.check_credentials()
            print(f"Credentials: {cred_message}")
        
        # Initialize progress bar
        progress_bar = ProgressBar(total_services)
        
        for i, service in enumerate(services_to_check.items(), 1):
            service_name, operations = service
            
            # Update main progress bar
            progress_bar.update(i, service_name)
            
            # Function to update API progress
            def update_api_progress(current, total):
                progress_bar.update_api(current, total)
            
            # Set progress callback
            self.progress_callback = update_api_progress
            
            # Scan the service
            service_results = self.scan_service_operations(service_name, operations)
            results[service_name] = service_results
            
            # Extract ARNs from error messages
            for op, result in service_results.items():
                if result.get('status') == 'denied' and 'message' in result:
                    arn = self._extract_arn_from_error(result['message'])
                    if arn:
                        unique_arns.add(arn)
            
            # Reset callback
            self.progress_callback = lambda x, y: None
        
        # Print newline after progress bar
        print()
        
        if RICH_AVAILABLE:
            console.print("[bold green]Scan complete![/bold green]")
        else:
            print("Scan complete!")
        
        # Print unique ARNs found
        if unique_arns:
            if RICH_AVAILABLE:
                console.print("\n[bold]Identity ARNs found in error messages:[/bold]")
                for arn in sorted(unique_arns):
                    console.print(f"ARN from error: [yellow]{arn}[/yellow]")
            else:
                print("\nIdentity ARNs found in error messages:")
                for arn in sorted(unique_arns):
                    print(f"ARN from error: {arn}")
        
        self.results = results
        return results

    def print_results(self, verbose=False):
        """Print scan results as a rich table"""
        allowed_count = 0
        denied_count = 0
        error_count = 0
        
        # Collect data for the table
        table_data = []
        
        # Group by service
        for service, operations in self.results.items():
            service_allowed = []
            service_denied = []
            service_error = []
            region = self.session.region_name or 'global'
            
            for operation, result in operations.items():
                status = result.get('status')
                if status == 'success':
                    service_allowed.append((operation, result))
                    allowed_count += 1
                elif status == 'denied':
                    service_denied.append((operation, result))
                    denied_count += 1
                else:
                    service_error.append((operation, result))
                    error_count += 1
            
            # Only include services with allowed operations if not verbose
            if not service_allowed and not verbose:
                continue
                
            # Add to table data
            if service_allowed:
                # Store operation names in kebab-case format for CLI
                allowed_ops = ", ".join(sorted([op[0].replace('_', '-') for op in service_allowed]))
                table_data.append([service, allowed_ops, region])
        
        # Print results using Rich if available, otherwise fallback to plain text
        if RICH_AVAILABLE:
            console = Console()
            
            # Create a rich table
            table = Table(title="AWS SDK Permissions Scan Results")
            table.add_column("Service", style="cyan", no_wrap=True)
            table.add_column("Allowed Operations", style="green")
            table.add_column("Region", style="magenta", no_wrap=True)
            
            # Add rows
            for row in sorted(table_data):
                service, allowed_ops, region = row
                table.add_row(service, allowed_ops, region)
            
            # Print the table
            console.print()
            console.print(table)
            
            # Print summary with rich formatting
            console.print()
            console.print(f"[bold]Summary:[/bold] Found [green]{allowed_count}[/green] allowed operations across [cyan]{len(table_data)}[/cyan] services")
            console.print(f"Total operations checked: [bold]{allowed_count + denied_count + error_count}[/bold]")
            
            if verbose:
                console.print(f"Denied operations: [yellow]{denied_count}[/yellow]")
                console.print(f"Error operations: [red]{error_count}[/red]")
        else:
            # Fallback to plain text table
            # Determine table width (total 100 characters)
            table_width = 100
            svc_col_width = 20
            region_col_width = 15
            perms_col_width = table_width - svc_col_width - region_col_width - 4  # 4 for borders
            
            # Print the table header
            print("\n" + "=" * table_width)
            print(f"{'Service':<{svc_col_width}} | {'Allowed Operations':<{perms_col_width}} | {'Region':<{region_col_width}}")
            print("=" * table_width)
            
            # Print the table rows
            for row in sorted(table_data):
                service, allowed_ops, region = row
                
                # Handle word wrapping for long permission lists
                if len(allowed_ops) <= perms_col_width:
                    # Simple case - fits on one line
                    print(f"{service:<{svc_col_width}} | {allowed_ops:<{perms_col_width}} | {region:<{region_col_width}}")
                else:
                    # We need to wrap the permissions
                    words = allowed_ops.split(", ")
                    lines = []
                    current_line = ""
                    
                    for word in words:
                        # Check if adding this word would exceed the column width
                        if len(current_line) + len(word) + 2 <= perms_col_width:  # +2 for ", "
                            if current_line:
                                current_line += ", " + word
                            else:
                                current_line = word
                        else:
                            # Line is full, start a new one
                            lines.append(current_line)
                            current_line = word
                    
                    # Add the last line if not empty
                    if current_line:
                        lines.append(current_line)
                    
                    # Print the first line with the service name
                    print(f"{service:<{svc_col_width}} | {lines[0]:<{perms_col_width}} | {region:<{region_col_width}}")
                    
                    # Print continuation lines
                    for line in lines[1:]:
                        print(f"{'':<{svc_col_width}} | {line:<{perms_col_width}} | {'':<{region_col_width}}")
            
            print("=" * table_width)
            
            # Print summary
            print(f"\nSummary: Found {allowed_count} operations across {len(table_data)} services")
            print(f"Total operations checked: {allowed_count + denied_count + error_count}")
            
            if verbose:
                print(f"Denied operations: {denied_count}")
                print(f"Error operations: {error_count}")
    
    def _get_response_summary(self, service, operation, response):
        """Get a concise summary of an API response"""
        if not response:
            return ""
            
        # Service-specific response processing
        if service == 's3' and operation == 'list_buckets':
            buckets = response.get('Buckets', [])
            return f"({len(buckets)} buckets)"
            
        elif service == 'iam' and operation == 'list_users':
            users = response.get('Users', [])
            return f"({len(users)} users)"
            
        elif service == 'iam' and operation == 'list_roles':
            roles = response.get('Roles', [])
            return f"({len(roles)} roles)"
            
        elif service == 'iam' and operation == 'list_groups':
            groups = response.get('Groups', [])
            return f"({len(groups)} groups)"
            
        elif service == 'ec2' and operation == 'describe_instances':
            reservations = response.get('Reservations', [])
            instance_count = sum(len(r.get('Instances', [])) for r in reservations)
            return f"({instance_count} instances)"
            
        elif service == 'ec2' and operation == 'describe_vpcs':
            vpcs = response.get('Vpcs', [])
            return f"({len(vpcs)} VPCs)"
            
        elif service == 'sqs' and operation == 'list_queues':
            queues = response.get('QueueUrls', [])
            return f"({len(queues)} queues)"
            
        elif service == 'sns' and operation == 'list_topics':
            topics = response.get('Topics', [])
            return f"({len(topics)} topics)"
            
        elif service == 'lambda' and operation == 'list_functions':
            functions = response.get('Functions', [])
            return f"({len(functions)} functions)"
            
        elif service == 'dynamodb' and operation == 'list_tables':
            tables = response.get('TableNames', [])
            return f"({len(tables)} tables)"
            
        elif service == 'rds' and operation == 'describe_db_instances':
            instances = response.get('DBInstances', [])
            return f"({len(instances)} DB instances)"
            
        elif service == 'secretsmanager' and operation == 'list_secrets':
            secrets = response.get('SecretList', [])
            return f"({len(secrets)} secrets)"
            
        return ""
    
    def save_results(self, filename):
        """Save scan results to a JSON file"""
        # Make results JSON-serializable
        serializable_results = {}
        
        for service, operations in self.results.items():
            serializable_results[service] = {}
            
            for operation, result in operations.items():
                serializable_op_result = result.copy()
                
                # Handle non-serializable response
                if 'response' in serializable_op_result:
                    serializable_op_result['response'] = json.loads(
                        json.dumps(serializable_op_result['response'], default=str)
                    )
                
                serializable_results[service][operation] = serializable_op_result
        
        with open(filename, 'w') as f:
            json.dump(serializable_results, f, indent=2)
            
        print(f"Results saved to {filename}")

    def generate_operations_by_service(self):
        """Dynamically generate list of operations to check for each service"""
        # Common read operations by service
        operations_by_service = {
            # Core services
            's3': ['list_buckets', 'get_bucket_location', 'get_bucket_policy'],
            'iam': ['list_users', 'list_roles', 'list_groups', 'list_policies', 'get_user', 'get_role'],
            'ec2': ['describe_instances', 'describe_vpcs', 'describe_security_groups', 'describe_subnets'],
            'sqs': ['list_queues'],
            'dynamodb': ['list_tables', 'describe_table'],
        }
        
        return operations_by_service


def main():
    parser = argparse.ArgumentParser(
        description='AWS SDK Permission Scanner - Scans AWS permissions using SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan default services with default profile
  python aws_enum_permissions.py run
  
  # Scan services from a file with a specific profile
  python aws_enum_permissions.py run --profile myprofile --operations-file targeted_operations.json --output results.json
  
  # Scan specific services in a specific region
  python aws_enum_permissions.py run --services iam,s3,ec2 --region us-west-2
  
  # Scan multiple regions
  python aws_enum_permissions.py run --regions us-east-1,us-west-2,eu-west-1
  
  # Show verbose output, including denied operations
  python aws_enum_permissions.py run --verbose
  
Notes:
  - The script tests AWS API operations to see which ones you have permission to call
  - Results show allowed operations for each service in kebab-case (e.g., list-users)
  - Operations file can be generated from aws_api_pull.py and used with --operations-file
  - Results can be saved to a JSON file for further analysis
  '''
    )
    
    parser.add_argument('action', nargs='?', help='Use "run" to execute the scan')
    parser.add_argument('--profile', type=str, help='AWS profile name from ~/.aws/credentials')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS region name (e.g., us-east-1)')
    parser.add_argument('--verbose', action='store_true', help='Show all operations including denied')
    parser.add_argument('--output', type=str, help='Save results to JSON file')
    parser.add_argument('--services', type=str, help='Comma-separated list of services to check (default: all)')
    parser.add_argument('--regions', type=str, help='Comma-separated list of regions to check (default: current region)')
    parser.add_argument('--operations-file', type=str, help='JSON file with service operations to check')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    # Show help by default if action is not "run"
    if args.action != 'run':
        parser.print_help()
        return
    
    # Check if rich is available and user doesn't want colors
    global RICH_AVAILABLE
    if args.no_color:
        RICH_AVAILABLE = False
    
    # Setup console for rich if available
    console = Console() if RICH_AVAILABLE else None
    
    # Determine regions to scan
    regions = [args.region]
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]
    
    all_results = {}
    
    # Scan each region
    for region in regions:
        if len(regions) > 1:
            if RICH_AVAILABLE:
                console.print(f"\nScanning region: [bold cyan]{region}[/bold cyan]")
            else:
                print(f"\nScanning region: {region}")
        
        # Initialize scanner for this region
        scanner = AWSSdkPermissionScanner(profile_name=args.profile, region_name=region)
        
        # Get operations to check
        if args.operations_file:
            try:
                with open(args.operations_file, 'r') as f:
                    kebab_operations = json.load(f)
                
                # Convert kebab-case to snake_case for boto3
                operations_by_service = {}
                for service, ops in kebab_operations.items():
                    operations_by_service[service] = [op.replace('-', '_') for op in ops]
                    
                if RICH_AVAILABLE:
                    console.print(f"Loaded operations from: [green]{args.operations_file}[/green]")
                else:
                    print(f"Loaded operations from: {args.operations_file}")
            except Exception as e:
                if RICH_AVAILABLE:
                    console.print(f"[bold red]Error loading operations file:[/bold red] {e}")
                    console.print("Falling back to default operations.")
                else:
                    print(f"Error loading operations file: {e}")
                    print("Falling back to default operations.")
                    
                operations_by_service = scanner.generate_operations_by_service()
        else:
            operations_by_service = scanner.generate_operations_by_service()
        
        # Filter services if specified
        if args.services:
            service_list = [s.strip() for s in args.services.split(',')]
            filtered_operations = {}
            for service in service_list:
                if service in operations_by_service:
                    filtered_operations[service] = operations_by_service[service]
                else:
                    if RICH_AVAILABLE:
                        console.print(f"[yellow]Warning:[/yellow] Service '{service}' not found in predefined services")
                    else:
                        print(f"Warning: Service '{service}' not found in predefined services")
            operations_by_service = filtered_operations
        
        # Scan permissions
        scanner.scan_services(operations_by_service)
        
        # Merge results if multiple regions
        if len(regions) > 1:
            all_results[region] = scanner.results
        else:
            all_results = scanner.results
        
        # Print results for this region
        scanner.print_results(verbose=args.verbose)
    
    # Save results if specified
    if args.output and len(regions) == 1:
        scanner.save_results(args.output)
        if RICH_AVAILABLE:
            console.print(f"\nResults saved to: [green]{args.output}[/green]")
    elif args.output:
        # Save multi-region results
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
            
        if RICH_AVAILABLE:
            console.print(f"\nResults saved to: [green]{args.output}[/green]")
        else:
            print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()