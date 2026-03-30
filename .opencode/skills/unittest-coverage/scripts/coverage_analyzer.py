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
Code Coverage Analyzer for Unit Test Generation

This script analyzes C++ source code to identify branches that need coverage
and generates recommendations for test cases.
"""

import re
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class Branch:
    """Represents a branch in the code"""
    file_path: str
    line_number: int
    branch_type: str  # if, else, switch, ternary, loop
    condition: str
    context: str
    is_virtual_function: bool
    function_name: str


@dataclass
class Function:
    """Represents a function"""
    name: str
    file_path: str
    start_line: int
    end_line: int
    is_virtual: bool
    return_type: str
    parameters: List[str]


class CoverageAnalyzer:
    """Analyzes code for branch coverage opportunities"""
    
    def __init__(self, source_paths: List[str]):
        self.source_paths = [Path(p) for p in source_paths]
        self.branches: List[Branch] = []
        self.functions: Dict[str, Function] = {}
        self.external_functions: Set[str] = set()
        
    def analyze(self) -> Dict:
        """Analyze all source files for branches and functions"""
        results = {
            'branches': [],
            'functions': [],
            'coverage_gaps': [],
            'recommendations': []
        }
        
        for source_path in self.source_paths:
            if source_path.is_file() and source_path.suffix in ['.cpp', '.h', '.hpp']:
                self._analyze_file(source_path)
            elif source_path.is_dir():
                for cpp_file in source_path.rglob('*.cpp'):
                    self._analyze_file(cpp_file)
                for header_file in source_path.rglob('*.h'):
                    self._analyze_file(header_file)
                for header_file in source_path.rglob('*.hpp'):
                    self._analyze_file(header_file)
        
        results['branches'] = [self._branch_to_dict(b) for b in self.branches]
        results['functions'] = [self._function_to_dict(f) for f in self.functions.values()]
        results['coverage_gaps'] = self._identify_coverage_gaps()
        results['recommendations'] = self._generate_recommendations()
        
        return results
    
    def _analyze_file(self, file_path: Path):
        """Analyze a single source file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return
        
        content = ''.join(lines)
        
        # Extract functions
        functions = self._extract_functions(file_path, lines)
        for func in functions:
            key = f"{func.name}:{file_path}"
            self.functions[key] = func
        
        # Extract branches
        branches = self._extract_branches(file_path, lines, functions)
        self.branches.extend(branches)
    
    def _extract_functions(self, file_path: Path, lines: List[str]) -> List[Function]:
        """Extract function definitions from source code"""
        functions = []
        content = ''.join(lines)
        
        # Pattern for function declarations
        func_pattern = re.compile(
            r'(?:virtual\s+)?(?:\w+(?:\s*::\s*\w+)?(?:<[^>]*>)?)\s+'  # return type
            r'(\w+)\s*'  # function name
            r'\(([^)]*)\)'  # parameters
            r'\s*(?:const\s*)?'  # const qualifier
            r'\s*(?:override\s*)?'  # override qualifier
            r'\s*\{'  # opening brace
        )
        
        for match in func_pattern.finditer(content):
            func_name = match.group(1)
            params = match.group(2)
            start_pos = match.start()
            start_line = content[:start_pos].count('\n') + 1
            
            # Check if virtual
            is_virtual = 'virtual' in content[max(0, start_pos-50):start_pos]
            
            # Find function end (matching braces)
            end_line = self._find_function_end(content, start_pos)
            
            # Extract return type
            return_type_match = re.search(
                r'((?:virtual\s+)?(?:\w+(?:\s*::\s*\w+)?(?:<[^>]*>)?)\s+)(?=\w+\s*\()',
                content[max(0, start_pos-100):start_pos]
            )
            return_type = return_type_match.group(1).strip() if return_type_match else 'auto'
            
            functions.append(Function(
                name=func_name,
                file_path=str(file_path),
                start_line=start_line,
                end_line=end_line,
                is_virtual=is_virtual,
                return_type=return_type,
                parameters=[p.strip() for p in params.split(',') if p.strip()]
            ))
        
        return functions
    
    def _find_function_end(self, content: str, start_pos: int) -> int:
        """Find the end line of a function by matching braces"""
        brace_count = 0
        in_function = False
        
        for i, char in enumerate(content[start_pos:], start=start_pos):
            if char == '{':
                brace_count += 1
                in_function = True
            elif char == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    return content[:i].count('\n') + 1
        
        return content[:start_pos].count('\n') + 1
    
    def _extract_branches(self, file_path: Path, lines: List[str], 
                         functions: List[Function]) -> List[Branch]:
        """Extract branch statements from source code"""
        branches = []
        content = ''.join(lines)
        
        # Find current function for each line
        func_map = {}
        for func in functions:
            for line in range(func.start_line, func.end_line + 1):
                func_map[line] = func
        
        # Pattern for if statements
        if_pattern = re.compile(r'\bif\s*\(([^)]+)\)')
        
        # Pattern for ternary operators
        ternary_pattern = re.compile(r'([^?]+)\s*\?\s*([^:]+)\s*:\s*([^;]+)')
        
        # Pattern for switch statements
        switch_pattern = re.compile(r'\bswitch\s*\(([^)]+)\)')
        
        # Pattern for loops (for, while)
        loop_pattern = re.compile(r'\b(for|while)\s*\(([^)]+)\)')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip comments
            if line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Check if statements
            if_match = if_pattern.search(line)
            if if_match:
                condition = if_match.group(1).strip()
                func = func_map.get(line_num)
                branches.append(Branch(
                    file_path=str(file_path),
                    line_number=line_num,
                    branch_type='if',
                    condition=condition,
                    context=line_stripped[:80],
                    is_virtual_function=func.is_virtual if func else False,
                    function_name=func.name if func else 'unknown'
                ))
            
            # Check ternary operators
            ternary_match = ternary_pattern.search(line)
            if ternary_match:
                condition = ternary_match.group(1).strip()
                func = func_map.get(line_num)
                branches.append(Branch(
                    file_path=str(file_path),
                    line_number=line_num,
                    branch_type='ternary',
                    condition=condition,
                    context=line_stripped[:80],
                    is_virtual_function=func.is_virtual if func else False,
                    function_name=func.name if func else 'unknown'
                ))
            
            # Check switch statements
            switch_match = switch_pattern.search(line)
            if switch_match:
                condition = switch_match.group(1).strip()
                func = func_map.get(line_num)
                branches.append(Branch(
                    file_path=str(file_path),
                    line_number=line_num,
                    branch_type='switch',
                    condition=condition,
                    context=line_stripped[:80],
                    is_virtual_function=func.is_virtual if func else False,
                    function_name=func.name if func else 'unknown'
                ))
            
            # Check loops
            loop_match = loop_pattern.search(line)
            if loop_match:
                condition = loop_match.group(2).strip()
                func = func_map.get(line_num)
                branches.append(Branch(
                    file_path=str(file_path),
                    line_number=line_num,
                    branch_type=loop_match.group(1),
                    condition=condition,
                    context=line_stripped[:80],
                    is_virtual_function=func.is_virtual if func else False,
                    function_name=func.name if func else 'unknown'
                ))
        
        return branches
    
    def _identify_coverage_gaps(self) -> List[Dict]:
        """Identify potential coverage gaps"""
        gaps = []
        
        # Group branches by function
        func_branches = defaultdict(list)
        for branch in self.branches:
            func_branches[branch.function_name].append(branch)
        
        # Analyze each function
        for func_name, branches in func_branches.items():
            if len(branches) < 2:
                continue
            
            # Check for missing test scenarios
            has_if = any(b.branch_type == 'if' for b in branches)
            has_else = any('else' in b.context for b in branches)
            
            if has_if and not has_else:
                gaps.append({
                    'type': 'missing_else_coverage',
                    'function': func_name,
                    'description': f'Function {func_name} has if statements but no else coverage detected',
                    'priority': 'medium'
                })
        
        return gaps
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate test case recommendations"""
        recommendations = []
        
        for branch in self.branches:
            if branch.branch_type == 'if':
                recommendations.append({
                    'type': 'branch_coverage',
                    'file': branch.file_path,
                    'line': branch.line_number,
                    'function': branch.function_name,
                    'branch_type': branch.branch_type,
                    'condition': branch.condition,
                    'mock_strategy': 'gmock' if branch.is_virtual_function else 'stub',
                    'recommendation': f'Create test cases for both true and false branches of condition: {branch.condition}',
                    'priority': 'high'
                })
            elif branch.branch_type in ['for', 'while']:
                recommendations.append({
                    'type': 'loop_coverage',
                    'file': branch.file_path,
                    'line': branch.line_number,
                    'function': branch.function_name,
                    'branch_type': branch.branch_type,
                    'condition': branch.condition,
                    'mock_strategy': 'gmock' if branch.is_virtual_function else 'stub',
                    'recommendation': f'Create test cases for loop: empty iteration, single iteration, multiple iterations',
                    'priority': 'high'
                })
        
        return recommendations
    
    def _branch_to_dict(self, branch: Branch) -> Dict:
        """Convert Branch to dictionary"""
        return {
            'file_path': branch.file_path,
            'line_number': branch.line_number,
            'branch_type': branch.branch_type,
            'condition': branch.condition,
            'context': branch.context,
            'is_virtual_function': branch.is_virtual_function,
            'function_name': branch.function_name
        }
    
    def _function_to_dict(self, func: Function) -> Dict:
        """Convert Function to dictionary"""
        return {
            'name': func.name,
            'file_path': func.file_path,
            'start_line': func.start_line,
            'end_line': func.end_line,
            'is_virtual': func.is_virtual,
            'return_type': func.return_type,
            'parameters': func.parameters
        }


def main():
    parser = argparse.ArgumentParser(
        description='Analyze C++ code for branch coverage opportunities'
    )
    parser.add_argument(
        'sources',
        nargs='+',
        help='Source files or directories to analyze'
    )
    parser.add_argument(
        '--output',
        '-o',
        help='Output file for analysis results (JSON)'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    analyzer = CoverageAnalyzer(args.sources)
    results = analyzer.analyze()
    
    if args.output:
        import json
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"Analysis results saved to {args.output}")
    
    if args.verbose:
        print(f"\nFound {len(results['branches'])} branches")
        print(f"Found {len(results['functions'])} functions")
        print(f"Identified {len(results['coverage_gaps'])} coverage gaps")
        print(f"Generated {len(results['recommendations'])} recommendations")
        
        if results['recommendations']:
            print("\nTop recommendations:")
            for rec in results['recommendations'][:5]:
                print(f"  - {rec['recommendation']}")
                print(f"    Mock strategy: {rec['mock_strategy']}")
                print(f"    File: {rec['file']}:{rec['line']}")


if __name__ == '__main__':
    main()
