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
Static Coverage Analyzer for C++ Unit Tests

Analyzes source code branches and test cases to infer coverage without running tests.
Identifies uncovered branches and generates test recommendations.
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class Branch:
    """Represents a branch in source code"""
    file: str
    line: int
    type: str  # 'if', 'else', 'switch', 'case', 'for', 'while', 'ternary'
    condition: str  # The condition expression
    function: str  # Containing function name
    likely_covered: bool = False
    covering_tests: List[str] = None

    def __post_init__(self):
        if self.covering_tests is None:
            self.covering_tests = []


@dataclass
class TestCase:
    """Represents a test case"""
    file: str
    name: str
    line: int
    function_under_test: str = ""
    input_values: Dict[str, any] = None
    assertions: List[str] = None
    mock_expectations: List[str] = None

    def __post_init__(self):
        if self.input_values is None:
            self.input_values = {}
        if self.assertions is None:
            self.assertions = []
        if self.mock_expectations is None:
            self.mock_expectations = []


@dataclass
class CoverageReport:
    """Coverage analysis report"""
    source_files: List[str]
    test_files: List[str]
    total_branches: int
    covered_branches: int
    coverage_percentage: float
    branches: List[dict]
    test_cases: List[dict]
    uncovered_branches: List[dict]
    recommendations: List[dict]


class CppParser:
    """C++ code parser for static analysis"""

    def __init__(self):
        self.branch_patterns = {
            'if': r'if\s*\(([^)]+)\)\s*\{',
            'else': r'\}\s*else\s*(?:if\s*\([^)]+\)\s*)?\{',
            'switch': r'switch\s*\(([^)]+)\)\s*\{',
            'case': r'case\s+([^:]+):',
            'for': r'for\s*\([^;]+;([^;]+);[^)]+\)\s*\{',
            'while': r'while\s*\(([^)]+)\)\s*\{',
            'ternary': r'([^=<>!]+)\s*\?\s*([^:]+)\s*:\s*([^;]+);',
        }

        self.test_patterns = {
            'hwtest': r'HWTEST_F\(([^,]+),\s*([^,]+),\s*[^)]+\)',
            'expect_eq': r'EXPECT_EQ\(([^,]+),\s*([^)]+)\)',
            'expect_ne': r'EXPECT_NE\(([^,]+),\s*([^)]+)\)',
            'expect_true': r'EXPECT_TRUE\(([^)]+)\)',
            'expect_false': r'EXPECT_FALSE\(([^)]+)\)',
            'expect_call': r'EXPECT_CALL\(([^,]+),\s*([^)]+)\)',
            'will_once': r'\.WillOnce\(([^)]+)\)',
            'return_value': r'Return\(([^)]+)\)',
        }

    def parse_source_file(self, filepath: str) -> Tuple[List[Branch], List[str]]:
        """Parse source file and extract branches and functions"""
        branches = []
        functions = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            current_function = ""
            in_function = False
            brace_count = 0

            for line_num, line in enumerate(lines, 1):
                # Track function definitions
                func_match = re.search(r'(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{', line)
                if func_match and not in_function:
                    current_function = func_match.group(1)
                    in_function = True
                    brace_count = line.count('{') - line.count('}')
                    functions.append(current_function)
                elif in_function:
                    brace_count += line.count('{') - line.count('}')
                    if brace_count == 0:
                        in_function = False
                        current_function = ""

                # Extract branches
                for branch_type, pattern in self.branch_patterns.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        condition = match.group(1) if match.groups() else ""
                        # Clean up condition
                        condition = re.sub(r'\s+', ' ', condition).strip()
                        
                        branch = Branch(
                            file=filepath,
                            line=line_num,
                            type=branch_type,
                            condition=condition,
                            function=current_function
                        )
                        branches.append(branch)

        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

        return branches, functions

    def parse_test_file(self, filepath: str) -> List[TestCase]:
        """Parse test file and extract test cases"""
        test_cases = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Find all test cases
            for line_num, line in enumerate(lines, 1):
                hwtest_match = re.search(self.test_patterns['hwtest'], line)
                if hwtest_match:
                    test_name = hwtest_match.group(2)
                    
                    # Extract test body (next ~30 lines or until next test)
                    test_body_lines = []
                    for i in range(line_num, min(line_num + 30, len(lines))):
                        if re.search(self.test_patterns['hwtest'], lines[i]) and i > line_num:
                            break
                        test_body_lines.append(lines[i])
                    
                    test_body = '\n'.join(test_body_lines)
                    
                    # Extract assertions
                    assertions = []
                    for pattern_name, pattern in self.test_patterns.items():
                        if pattern_name.startswith('expect_'):
                            matches = re.findall(pattern, test_body)
                            assertions.extend(matches)
                    
                    # Extract mock expectations
                    mock_expectations = []
                    expect_calls = re.findall(self.test_patterns['expect_call'], test_body)
                    for mock_obj, mock_method in expect_calls:
                        will_once = re.search(self.test_patterns['will_once'], test_body)
                        if will_once:
                            mock_expectations.append(f"{mock_obj}.{mock_method} -> {will_once.group(1)}")
                    
                    # Extract input values (simplified)
                    input_values = self._extract_input_values(test_body)
                    
                    # Infer function under test
                    function_under_test = self._infer_function_under_test(test_body, test_name)
                    
                    test_case = TestCase(
                        file=filepath,
                        name=test_name,
                        line=line_num,
                        function_under_test=function_under_test,
                        input_values=input_values,
                        assertions=assertions,
                        mock_expectations=mock_expectations
                    )
                    test_cases.append(test_case)

        except Exception as e:
            print(f"Error parsing test file {filepath}: {e}")

        return test_cases

    def _extract_input_values(self, test_body: str) -> Dict[str, any]:
        """Extract input values from test body"""
        input_values = {}
        
        # Extract variable assignments
        var_patterns = [
            r'int\s+(\w+)\s*=\s*(\d+);',
            r'bool\s+(\w+)\s*=\s*(true|false);',
            r'std::string\s+(\w+)\s*=\s*"([^"]*)";',
            r'(\w+)\s+(\w+)\s*=\s*(\w+);',
        ]
        
        for pattern in var_patterns:
            matches = re.findall(pattern, test_body)
            for match in matches:
                if len(match) == 2:
                    var_name, value = match
                    input_values[var_name] = value
                elif len(match) == 3:
                    var_type, var_name, value = match
                    input_values[var_name] = value

        return input_values

    def _infer_function_under_test(self, test_body: str, test_name: str) -> str:
        """Infer the function under test from test name and body"""
        # Extract function name from test name (e.g., "GetSlotType_00001" -> "GetSlotType")
        func_match = re.match(r'(\w+)_\d+', test_name)
        if func_match:
            return func_match.group(1)
        
        # Look for function calls in test body
        func_calls = re.findall(r'(\w+)\s*\([^)]*\);', test_body)
        if func_calls:
            # Return the most frequent function call (likely the function under test)
            from collections import Counter
            counter = Counter(func_calls)
            return counter.most_common(1)[0][0]
        
        return ""


class CoverageAnalyzer:
    """Main coverage analyzer"""

    def __init__(self, verbose: bool = False):
        self.parser = CppParser()
        self.verbose = verbose
        self.source_branches = []
        self.test_cases = []

    def analyze(self, source_paths: List[str], test_paths: List[str]) -> CoverageReport:
        """Analyze coverage"""
        print("Analyzing source code...")
        self._analyze_source(source_paths)
        
        print("Analyzing test cases...")
        self._analyze_tests(test_paths)
        
        print("Inferring coverage...")
        self._infer_coverage()
        
        print("Generating recommendations...")
        recommendations = self._generate_recommendations()
        
        report = self._generate_report(recommendations)
        return report

    def _analyze_source(self, paths: List[str]):
        """Analyze source files"""
        for path in paths:
            if os.path.isfile(path):
                self._parse_source_file(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith(('.cpp', '.h', '.hpp')):
                            filepath = os.path.join(root, file)
                            self._parse_source_file(filepath)

    def _parse_source_file(self, filepath: str):
        """Parse a single source file"""
        branches, functions = self.parser.parse_source_file(filepath)
        self.source_branches.extend(branches)
        
        if self.verbose:
            print(f"  {filepath}: {len(branches)} branches")

    def _analyze_tests(self, paths: List[str]):
        """Analyze test files"""
        for path in paths:
            if os.path.isfile(path):
                self._parse_test_file(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith('_test.cpp'):
                            filepath = os.path.join(root, file)
                            self._parse_test_file(filepath)

    def _parse_test_file(self, filepath: str):
        """Parse a single test file"""
        test_cases = self.parser.parse_test_file(filepath)
        self.test_cases.extend(test_cases)
        
        if self.verbose:
            print(f"  {filepath}: {len(test_cases)} test cases")

    def _infer_coverage(self):
        """Infer which branches are covered by test cases"""
        for branch in self.source_branches:
            for test_case in self.test_cases:
                if self._is_branch_covered(branch, test_case):
                    branch.likely_covered = True
                    branch.covering_tests.append(test_case.name)

    def _is_branch_covered(self, branch: Branch, test_case: TestCase) -> bool:
        """Check if a branch is likely covered by a test case"""
        # Check if test is for the same function
        if branch.function and test_case.function_under_test:
            if not self._function_names_match(branch.function, test_case.function_under_test):
                return False
        
        # Check input values against branch condition
        if self._condition_satisfied(branch, test_case):
            return
        
        # Check mock expectations
        if self._mock_satisfies_branch(branch, test_case):
            return True
        
        return False

    def _function_names_match(self, func1: str, func2: str) -> bool:
        """Check if function names match (case-insensitive, partial match)"""
        return func1.lower() in func2.lower() or func2.lower() in func1.lower()

    def _condition_satisfied(self, branch: Branch, test_case: TestCase) -> bool:
        """Check if test case inputs satisfy branch condition"""
        if not branch.condition:
            return False
        
        condition = branch.condition.lower()
        
        # Simple pattern matching
        for var_name, value in test_case.input_values.items():
            var_pattern = var_name.lower()
            
            # Check for comparison operators
            if f'{var_pattern} >' in condition:
                try:
                    if int(value) > 0:
                        return True
                except ValueError:
                    pass
            elif f'{var_pattern} <' in condition:
                try:
                    if int(value) < 0:
                        return True
                except ValueError:
                    pass
            elif f'{var_pattern} ==' in condition or f'{var_pattern} !=' in condition:
                return True
            elif var_pattern in condition:
                return True
        
        return False

    def _mock_satisfies_branch(self, branch: Branch, test_case: TestCase) -> bool:
        """Check if mock expectations satisfy branch condition"""
        for mock_expectation in test_case.mock_expectations:
            if 'Return' in mock_expectation:
                return True
        return False

    def _generate_recommendations(self) -> List[dict]:
        """Generate test recommendations for uncovered branches"""
        recommendations = []
        
        for branch in self.source_branches:
            if not branch.likely_covered:
                recommendation = {
                    'file': branch.file,
                    'line': branch.line,
                    'function': branch.function,
                    'branch_type': branch.type,
                    'condition': branch.condition,
                    'priority': self._calculate_priority(branch),
                    'mock_strategy': self._determine_mock_strategy(branch),
                    'test_suggestion': self._generate_test_suggestion(branch)
                }
                recommendations.append(recommendation)
        
        # Sort by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return recommendations

    def _calculate_priority(self, branch: Branch) -> str:
        """Calculate priority for a branch"""
        # High priority: if/else branches with conditions
        if branch.type in ['if', 'else'] and branch.condition:
            return 'high'
        
        # Medium priority: loops and switches
        if branch.type in ['for', 'while', 'switch', 'case']:
            return 'medium'
        
        # Low priority: ternary operators
        return 'low'

    def _determine_mock_strategy(self, branch: Branch) -> str:
        """Determine mock strategy for a branch"""
        # This is a simplified heuristic
        # In practice, you'd need to analyze the function signature
        return 'gmock' if branch.function else 'stub'

    def _generate_test_suggestion(self, branch: Branch) -> str:
        """Generate a test suggestion for a branch"""
        if branch.type == 'if':
            return f"Test condition '{branch.condition}' with true/false values"
        elif branch.type == 'else':
            return f"Test else branch of function '{branch.function}'"
        elif branch.type == 'for':
            return f"Test loop with empty, single, and multiple iterations"
        elif branch.type == 'switch':
            return f"Test switch case '{branch.condition}' and default case"
        else:
            return f"Test {branch.type} branch in function: {branch.function}"

    def _generate_report(self, recommendations: List[dict]) -> CoverageReport:
        """Generate final coverage report"""
        total_branches = len(self.source_branches)
        covered_branches = sum(1 for b in self.source_branches if b.likely_covered)
        coverage_percentage = (covered_branches / total_branches * 100) if total_branches > 0 else 0
        
        uncovered_branches = [
            asdict(branch) for branch in self.source_branches 
            if not branch.likely_covered
        ]
        
        report = CoverageReport(
            source_files=list(set(b.file for b in self.source_branches)),
            test_files=list(set(t.file for t in self.test_cases)),
            total_branches=total_branches,
            covered_branches=covered_branches,
            coverage_percentage=round(coverage_percentage, 2),
            branches=[asdict(b) for b in self.source_branches],
            test_cases=[asdict(t) for t in self.test_cases],
            uncovered_branches=uncovered_branches,
            recommendations=recommendations
        )
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Static Coverage Analyzer for C++ Unit Tests'
    )
    parser.add_argument(
        'source_paths',
        nargs='+',
        help='Source files or directories to analyze'
    )
    parser.add_argument(
        '--test-paths',
        nargs='+',
        help='Test files or directories to analyze'
    )
    parser.add_argument(
        '--output',
        '-o',
        default='coverage_report.json',
        help='Output JSON file (default: coverage_report.json)'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # If test paths not specified, look for test directories
    test_paths = args.test_paths
    if not test_paths:
        test_paths = []
        for source_path in args.source_paths:
            if os.path.isdir(source_path):
                # Look for test directories
                for root, dirs, files in os.walk(source_path):
                    if 'test' in dirs:
                        test_paths.append(os.path.join(root, 'test'))
                    if 'unittest' in dirs:
                        test_paths.append(os.path.join(root, 'unittest'))
    
    # Run analysis
    analyzer = CoverageAnalyzer(verbose=args.verbose)
    report = analyzer.analyze(args.source_paths, test_paths)
    
    # Save report
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(asdict(report), f, indent=2, ensure_ascii=False)
    
    # Print summary
    print(f"\n{'='*60}")
    print("Coverage Analysis Summary")
    print(f"{'='*60}")
    print(f"Source files: {len(report.source_files)}")
    print(f"Test files: {len(report.test_files)}")
    print(f"Total branches: {report.total_branches}")
    print(f"Covered branches: {report.covered_branches}")
    print(f"Coverage: {report.coverage_percentage}%")
    print(f"Uncovered branches: {len(report.uncovered_branches)}")
    print(f"Recommendations: {len(report.recommendations)}")
    print(f"{'='*60}")
    print(f"\nReport saved to: {args.output}")
    
    # Print top recommendations
    if report.recommendations:
        print(f"\nTop 5 Recommendations:")
        print(f"{'-'*60}")
        for i, rec in enumerate(report.recommendations[:5], 1):
            print(f"{i}. [{rec['priority'].upper()}] {rec['file']}:{rec['line']}")
            print(f"   Function: {rec['function']}")
            print(f"   Branch: {rec['branch_type']} - {rec['condition']}")
            print(f"   Suggestion: {rec['test_suggestion']}")
            print(f"   Mock Strategy: {rec['mock_strategy']}")
            print()


if __name__ == '__main__':
    main()
