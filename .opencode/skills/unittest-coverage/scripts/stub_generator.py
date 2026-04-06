#!/usr/bin/env python3
# coding=utf-8

# Copyright (C) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Stub Generator for Unit Tests

This script generates stub implementations for external functions that need to be mocked.
"""

import re
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class ExternalFunction:
    """Represents an external function call"""
    name: str
    return_type: str
    parameters: List[str]
    file_path: str
    line_number: int
    context: str


class StubGenerator:
    """Generates stub implementations for external functions"""
    
    def __init__(self, source_paths: List[str]):
        self.source_paths = [Path(p) for p in source_paths]
        self.external_functions: List[ExternalFunction] = []
        
    def analyze(self) -> Dict:
        """Analyze source files for external function calls"""
        results = {
            'external_functions': [],
            'stubs': []
        }
        
        for source_path in self.source_paths:
            if source_path.is_file() and source_path.suffix in ['.cpp', '.h', '.hpp']:
                self._analyze_file(source_path)
            elif source_path.is_dir():
                for cpp_file in source_path.rglob('*.cpp'):
                    self._analyze_file(cpp_file)
        
        results['external_functions'] = [self._func_to_dict(f) for f in self.external_functions]
        results['stubs'] = self._generate_stubs()
        
        return results
    
    def _analyze_file(self, file_path: Path):
        """Analyze a single source file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return
        
        # Pattern for external function calls (non-member functions)
        # This is a simplified pattern - real implementation would need more sophisticated parsing
        external_call_pattern = re.compile(
            r'(\w+)\s*\('  # function name followed by (
        )
        
        # Common external function prefixes to avoid
        internal_prefixes = ['if', 'for', 'while', 'switch', 'return', 'sizeof', 
                           'new', 'delete', 'static_cast', 'dynamic_cast', 
                           'reinterpret_cast', 'const_cast']
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip comments
            if line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Look for function calls
            for match in external_call_pattern.finditer(line):
                func_name = match.group(1)
                
                # Skip internal keywords
                if func_name in internal_prefixes:
                    continue
                
                # Skip member function calls (contains :: or .)
                if '::' in func_name or '.' in func_name:
                    continue
                
                # Check if this looks like an external function
                if self._is_external_function(func_name, line):
                    self.external_functions.append(ExternalFunction(
                        name=func_name,
                        return_type='auto',  # Would need type inference
                        parameters=[],  # Would need parameter extraction
                        file_path=str(file_path),
                        line_number=line_num,
                        context=line_stripped[:80]
                    ))
    
    def _is_external_function(self, func_name: str, line: str) -> bool:
        """Determine if a function call is likely external"""
        # This is a heuristic - real implementation would use AST parsing
        
        # Check if it's a standard library function
        std_patterns = ['std::', 'printf', 'scanf', 'malloc', 'free', 
                       'strlen', 'strcpy', 'strcmp', 'memcpy', 'memset']
        
        for pattern in std_patterns:
            if pattern in line:
                return True
        
        # Check if it's not a method call (no -> or . before function name)
        func_pos = line.find(func_name)
        if func_pos > 0:
            prev_char = line[func_pos - 1]
            if prev_char in ['.', '>', ':']:
                return False
        
        return True
    
    def _generate_stubs(self) -> List[Dict]:
        """Generate stub implementations"""
        stubs = []
        seen_functions = set()
        
        for func in self.external_functions:
            if func.name in seen_functions:
                continue
            seen_functions.add(func.name)
            
            stub = {
                'function_name': func.name,
                'header_content': self._generate_stub_header(func),
                'implementation_content': self._generate_stub_implementation(func),
                'usage_example': self._generate_usage_example(func)
            }
            stubs.append(stub)
        
        return stubs
    
    def _generate_stub_header(self, func: ExternalFunction) -> str:
        """Generate stub header content"""
        return f"""// Stub for external function: {func.name}
// Generated automatically - modify as needed

#ifndef STUB_{func.name.upper()}_H
#define STUB_{func.name.upper()}_H

#include <functional>

namespace Stub {{
    // Static control for stub behavior
    static bool {func.name}_enabled = false;
    static auto {func.name}_return_value = decltype({func.name}()){{}};
    static std::function<decltype({func.name})()> {func.name}_callback = nullptr;

    // Enable/disable stub
    inline void Set{func.name}StubEnabled(bool enabled) {{
        {func.name}_enabled = enabled;
    }}

    // Set return value for stub
    inline void Set{func.name}ReturnValue(decltype({func.name}()) value) {{
        {func.name}_return_value = value;
    }}

    // Set custom callback for stub
    inline void Set{func.name}Callback(std::function<decltype({func.name})()> callback) {{
        {func.name}_callback = callback;
    }}

    // Reset stub to default state
    inline void Reset{func.name}Stub() {{
        {func.name}_enabled = false;
        {func.name}_callback = nullptr;
    }}
}}

#endif // STUB_{func.name.upper()}_H
"""
    
    def _generate_stub_implementation(self, func: ExternalFunction) -> str:
        """Generate stub implementation content"""
        return f"""// Stub implementation for: {func.name}
// Link this file with your test to override the external function

#include "stub_{func.name}.h"

// Override the external function
extern "C" decltype({func.name}()) {func.name}({{ /* parameters */ }}) {{
    if (Stub::{func.name}_enabled) {{
        if (Stub::{func.name}_callback) {{
            return Stub::{func.name}_callback();
        }}
        return Stub::{func.name}_return_value;
    }}
    
    // Call original function (link with --wrap linker flag)
    return __real_{func.name}({{ /* parameters */ }});
}}
"""
    
    def _generate_usage_example(self, func: ExternalFunction) -> str:
        """Generate usage example"""
        return f"""// Example usage in test:

#include "stub_{func.name}.h"

TEST(MyTest, TestWith{func.name}Stub) {{
    // Enable stub
    Stub::Set{func.name}StubEnabled(true);
    
    // Set return value
    Stub::Set{func.name}ReturnValue(expected_value);
    
    // Or set custom callback
    Stub::Set{func.name}Callback([]() {{
        return custom_logic();
    }});
    
    // Run test
    // ... test code ...
    
    // Reset stub
    Stub::Reset{func.name}Stub();
}}
"""
    
    def _func_to_dict(self, func: ExternalFunction) -> Dict:
        """Convert ExternalFunction to dictionary"""
        return {
            'name': func.name,
            'return_type': func.return_type,
            'parameters': func.parameters,
            'file_path': func.file_path,
            'line_number': func.line_number,
            'context': func.context
        }


def main():
    parser = argparse.ArgumentParser(
        description='Generate stub implementations for external functions'
    )
    parser.add_argument(
        'sources',
        nargs='+',
        help='Source files or directories to analyze'
    )
    parser.add_argument(
        '--output-dir',
        '-o',
        help='Output directory for generated stub files'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    generator = StubGenerator(args.sources)
    results = generator.analyze()
    
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for stub in results['stubs']:
            # Write header file
            header_file = output_dir / f"stub_{stub['function_name']}.h"
            with open(header_file, 'w', encoding='utf-8') as f:
                f.write(stub['header_content'])
            
            # Write implementation file
            impl_file = output_dir / f"stub_{stub['function_name']}.cpp"
            with open(impl_file, 'w', encoding='utf-8') as f:
                f.write(stub['implementation_content'])
            
            # Write usage example
            example_file = output_dir / f"stub_{stub['function_name']}_example.txt"
            with open(example_file, 'w', encoding='utf-8') as f:
                f.write(stub['usage_example'])
        
        print(f"Generated {len(results['stubs'])} stub files in {args.output_dir}")
    
    if args.verbose:
        print(f"\nFound {len(results['external_functions'])} external function calls")
        print(f"Generated {len(results['stubs'])} stub implementations")
        
        if results['stubs']:
            print("\nGenerated stubs:")
            for stub in results['stubs']:
                print(f"  - {stub['function_name']}")


if __name__ == '__main__':
    main()
