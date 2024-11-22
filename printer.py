import math
import os
import datetime
from colorama import init, Fore, Style
from collections import defaultdict
import mimetypes
import threading
import fnmatch
from pathlib import Path
import json

# Initialize colorama for cross-platform color support
init()

class DirectoryAnalyzer:
    def __init__(self, exclude_patterns=None, exclude_file=None):
        self.total_size = 0
        self.file_types = defaultdict(int)
        self.file_counts = defaultdict(int)
        self.largest_files = []
        self.newest_files = []
        self.lock = threading.Lock()
        
        # Load default exclude patterns
        self.exclude_patterns = {
            'dirs': set(['.git', '.svn', '__pycache__', 'node_modules', 'venv', '.env']),
            'files': set(['*.pyc', '*.pyo', '*.pyd', '.DS_Store', 'Thumbs.db']),
            'custom': set()
        }
        
        # Add user-provided patterns
        if exclude_patterns:
            for pattern in exclude_patterns:
                if pattern.endswith('/'):
                    self.exclude_patterns['dirs'].add(pattern.rstrip('/'))
                else:
                    self.exclude_patterns['files'].add(pattern)
        
        # Load patterns from exclude file if provided
        if exclude_file:
            self.load_exclude_patterns(exclude_file)

    def load_exclude_patterns(self, exclude_file):
        """Load exclude patterns from a JSON file"""
        try:
            with open(exclude_file, 'r') as f:
                patterns = json.load(f)
                if isinstance(patterns, dict):
                    for key in ['dirs', 'files', 'custom']:
                        if key in patterns:
                            self.exclude_patterns[key].update(patterns[key])
                elif isinstance(patterns, list):
                    for pattern in patterns:
                        if pattern.endswith('/'):
                            self.exclude_patterns['dirs'].add(pattern.rstrip('/'))
                        else:
                            self.exclude_patterns['files'].add(pattern)
        except Exception as e:
            print(f"{Fore.RED}Error loading exclude patterns: {str(e)}{Style.RESET_ALL}")

    def should_exclude(self, path, name):
        """Check if a path should be excluded based on patterns"""
        # Check directory patterns
        if os.path.isdir(os.path.join(path, name)):
            if name in self.exclude_patterns['dirs']:
                return True
            for pattern in self.exclude_patterns['custom']:
                if pattern.endswith('/') and fnmatch.fnmatch(name, pattern.rstrip('/')):
                    return True
        
        # Check file patterns
        for pattern in self.exclude_patterns['files']:
            if fnmatch.fnmatch(name, pattern):
                return True
        
        # Check custom patterns
        for pattern in self.exclude_patterns['custom']:
            if not pattern.endswith('/') and fnmatch.fnmatch(name, pattern):
                return True
            
        return False

    def convert_size(self, size_bytes):
        """Convert bytes to human readable format with proper rounding"""
        if size_bytes == 0:
            return "0 B"
        size_names = ('B', 'KB', 'MB', 'GB', 'TB', 'PB')
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"

    def get_mime_type(self, filepath):
        """Get the MIME type of a file"""
        return mimetypes.guess_type(filepath)[0] or "application/octet-stream"

    def process_file(self, filepath):
        """Process a single file for statistics"""
        try:
            stats = os.stat(filepath)
            size = stats.st_size
            modified_time = datetime.datetime.fromtimestamp(stats.st_mtime)
            file_type = self.get_mime_type(filepath)

            with self.lock:
                self.total_size += size
                self.file_types[file_type] += 1
                self.file_counts['files'] += 1
                
                # Track largest files
                self.largest_files.append((filepath, size))
                self.largest_files.sort(key=lambda x: x[1], reverse=True)
                self.largest_files = self.largest_files[:5]
                
                # Track newest files
                self.newest_files.append((filepath, modified_time))
                self.newest_files.sort(key=lambda x: x[1], reverse=True)
                self.newest_files = self.newest_files[:5]

            return size, file_type
        except (OSError, IOError) as e:
            print(f"{Fore.RED}Error processing {filepath}: {str(e)}{Style.RESET_ALL}")
            return 0, None

    def get_dir_size_fast(self, path):
        """Quickly get directory size using os.scandir"""
        total = 0
        try:
            with os.scandir(path) as it:
                for entry in it:
                    if self.should_exclude(path, entry.name):
                        continue
                    try:
                        if entry.is_file():
                            total += entry.stat().st_size
                        elif entry.is_dir():
                            total += self.get_dir_size_fast(entry.path)
                    except (OSError, IOError):
                        continue
        except (OSError, IOError):
            pass
        return total

    def get_color_for_file(self, filename):
        """Determine color based on file extension"""
        if filename.endswith(('.py', '.java', '.cpp', '.js', '.html')):
            return Fore.YELLOW
        elif filename.endswith(('.jpg', '.png', '.gif', '.bmp')):
            return Fore.MAGENTA
        elif filename.endswith(('.zip', '.tar', '.gz', '.rar')):
            return Fore.RED
        elif filename.endswith(('.dat', '.parquet', '.csv')):
            return Fore.CYAN
        else:
            return Fore.GREEN

    def print_tree(self, start_path, prefix="", level=0, max_level=None):
        """Print directory tree with enhanced information"""
        if max_level is not None and level > max_level:
            return

        try:
            items = sorted(os.listdir(start_path))
        except PermissionError:
            print(f"{Fore.RED}Permission denied: {start_path}{Style.RESET_ALL}")
            return

        # Filter out excluded items
        items = [item for item in items if not self.should_exclude(start_path, item)]

        for idx, item in enumerate(items):
            is_last_item = idx == len(items) - 1
            full_path = os.path.join(start_path, item)
            connector = "└──" if is_last_item else "├──"

            try:
                stats = os.stat(full_path)
                modified_time = datetime.datetime.fromtimestamp(stats.st_mtime)
                
                if os.path.isdir(full_path):
                    dir_size = self.get_dir_size_fast(full_path)
                    
                    with self.lock:
                        self.file_counts['directories'] += 1
                    
                    print(f"{prefix}{connector} {Fore.BLUE}{item}/{Style.RESET_ALL}")
                    info = f"{Fore.CYAN}[DIR]{Style.RESET_ALL} {self.convert_size(dir_size)}, "
                    info += f"{len([f for f in os.listdir(full_path) if not self.should_exclude(full_path, f)])} items, "
                    info += f"Modified: {modified_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(f"{prefix}{'    ' if is_last_item else '│   '} {info}")
                    
                    extension = "    " if is_last_item else "│   "
                    self.print_tree(full_path, prefix + extension, level + 1, max_level)
                else:
                    size = stats.st_size
                    color = self.get_color_for_file(item)
                    
                    print(f"{prefix}{connector} {color}{item}{Style.RESET_ALL}")
                    info = f"{Fore.GREEN}[FILE]{Style.RESET_ALL} {self.convert_size(size)}, "
                    info += f"Modified: {modified_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(f"{prefix}{'    ' if is_last_item else '│   '} {info}")

                    # Process file statistics asynchronously
                    self.process_file(full_path)

            except (OSError, IOError) as e:
                print(f"{prefix}{connector} {Fore.RED}{item} (Error: {str(e)}){Style.RESET_ALL}")

    def print_summary(self):
        """Print summary statistics"""
        print(f"\n{Fore.CYAN}=== Directory Analysis Summary ==={Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Storage Statistics:{Style.RESET_ALL}")
        print(f"Total Size: {self.convert_size(self.total_size)}")
        print(f"Total Files: {self.file_counts['files']}")
        print(f"Total Directories: {self.file_counts['directories']}")

        print(f"\n{Fore.YELLOW}Largest Files:{Style.RESET_ALL}")
        for filepath, size in self.largest_files:
            print(f"- {os.path.basename(filepath)}: {self.convert_size(size)}")

        print(f"\n{Fore.YELLOW}Most Recent Files:{Style.RESET_ALL}")
        for filepath, modified_time in self.newest_files:
            print(f"- {os.path.basename(filepath)}: {modified_time.strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\n{Fore.YELLOW}File Type Distribution:{Style.RESET_ALL}")
        for file_type, count in sorted(self.file_types.items(), key=lambda x: x[1], reverse=True):
            print(f"- {file_type}: {count} files")

        print(f"\n{Fore.YELLOW}Active Exclude Patterns:{Style.RESET_ALL}")
        print("Directories:", ', '.join(sorted(self.exclude_patterns['dirs'])))
        print("Files:", ', '.join(sorted(self.exclude_patterns['files'])))
        if self.exclude_patterns['custom']:
            print("Custom:", ', '.join(sorted(self.exclude_patterns['custom'])))

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced directory tree analyzer')
    parser.add_argument('path', nargs='?', default='.', help='Starting directory path')
    parser.add_argument('--max-level', type=int, help='Maximum depth to traverse')
    parser.add_argument('--no-color', action='store_true', help='Disable color output')
    parser.add_argument('--no-summary', action='store_true', help='Skip summary statistics')
    parser.add_argument('--exclude', '-e', action='append', help='Patterns to exclude (append / for directories)')
    parser.add_argument('--exclude-file', help='JSON file containing exclude patterns')
    
    args = parser.parse_args()
    
    if args.no_color:
        init(strip=True)
    
    print(f"\n{Fore.CYAN}Directory Tree for: {args.path}{Style.RESET_ALL}\n")
    
    analyzer = DirectoryAnalyzer(args.exclude, args.exclude_file)
    analyzer.print_tree(args.path, max_level=args.max_level)
    
    if not args.no_summary:
        analyzer.print_summary()

if __name__ == "__main__":
    main()