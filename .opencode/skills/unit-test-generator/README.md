# Unit Test Generator Skill

Generate comprehensive unit tests for OpenHarmony Distributed Notification Service that follow project standards include proper assertions use appropriate mocks and achieve 90% branch coverage.

## Overview

This skill provides guidance and templates for generating unit tests for the OpenHarmony Distributed Notification Service codebase. It ensures all generated tests follow project standards, include proper assertions, use appropriate mocks, and achieve 90%+ branch coverage.

## Documentation Structure

- **[SKILL.md](SKILL.md)** - Main workflow and templates
- **[references/TEST_PATTERNS.md](references/TEST_PATTERNS.md)** - 10 essential test patterns
- **[references/MOCK_REFERENCES.md](references/MOCK_REFERENCES.md)** - 5 common mock libraries
- **[references/MOCK_CREATION_GUIDE.md](references/MOCK_CREATION_GUIDE.md)** - Mock creation guide
- **[references/BUILD_CONFIG.md](references/BUILD_CONFIG.md)** - BUILD.gn configuration reference

## Workflow Overview

1. **Identify Test Scope** - Determine what to test (new code, commit, or file)
2. **Analyze Source Code** - Extract classes, functions, and dependencies
3. **Determine Mock Requirements** - Select appropriate mocks
4. **Generate Test Cases** - Create tests following project standards
5. **Update BUILD.gn** - Add test files and dependencies
6. **Build and Verify** - Compile and run tests, check coverage

## Coverage Requirements

**Target:** 90%+ branch coverage for all tested code

## Quality Checks

Before completing test generation, verify:

- [ ] Every test has at least one assertion (EXPECT/ASSERT)
- [ ] All tests follow naming convention: `FunctionName_ScenarioNumber`
- [ ] Test documentation includes @tc.name, @tc.desc, @tc.type, @tc.require
- [ ] Appropriate mocks are included and used correctly
- [ ] BUILD.gn is updated with new test source
- [ ] Test compiles without errors
- [ ] Test executes successfully
- [ ] Branch coverage meets 90% requirement

## License

Copyright (c) 2026 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
