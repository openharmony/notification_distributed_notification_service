# BUILD.gn Configuration Reference

This document provides BUILD.gn configuration templates for unit tests in the Distributed Notification Service.

## Basic Test Target

### Standard Test

```gn
ohos_unittest("test_name") {
  module_out_path = module_output_path

  include_dirs = [
    ".",
    "include",
    "/${services_path}/module/include",
    "${services_path}/module/test/unittest/mock/include",
  ]

  sources = [
    "test_file.cpp",
  ]

  cflags = [
    "-Dprivate=public",
    "-Dprotected=public",
  ]

  deps = [
    "${frameworks_path}:module_innerkits",
    "${services_path}/module:libmodule:mock_source",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"
}
```

### Test with Exception Support

```gn
ohos_unittest("test_name") {
  module_out_path = module_output_path

  include_dirs = [
    ".",
    "include",
    "/${services_path}/module/include",
    "${services_path}/module/test/unittest/mock/include",
  ]

  sources = [
    "test_file.cpp",
  ]

  cflags = [
    "-Dprivate=public",
    "-Dprotected=public",
  ]

  # Required for EXPECT_THROW/EXPECT_NO_THROW
  use_exceptions = true

  deps = [
    "${frameworks_path}:module_innerkits",
    "${services_path}/module:libmodule:mock_source",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"
}
```

## Common External Dependencies

### Core Dependencies

```gn
external_deps = [
  "hilog:libhilog",
  "ipc:ipc_core",
  "safwk:system_ability_fwk",
  "samgr:samgr_proxy",
]
```

### Bundle Framework

```gn
external_deps = [
  "bundle_framework:appexecfwk_base",
  "bundle_framework:appexecfwk_core",
]
```

### Data Storage

```gn
external_deps = [
  "kv_store:distributeddata_inner",
  "relational_store:native_rdb",
]
```

### Security

```gn
external_deps = [
  "access_token:libnativetoken",
  "access_token:libtoken_setproc",
]
```

## Common Internal Dependencies

### Mock Dependencies

```gn
deps = [
  "${services_path}/module:libmodule:mock_source",
]
```

### Framework Dependencies

```gn
deps = [
  "${frameworks_path}:module_innerkits",
]
```

## Complete Example

```gn
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-arez0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import("//build/test.gni")

ohos_unittest("notification_slot_test") {
  module_out_path = "${component_name}/distributed_notification_service/unittest"

  include_dirs = [
    ".",
    "include",
    "/${services_path}/ans/include",
    "${services_path}/ans/test/unittest/mock/include",
  ]

  sources = [
    "notification_slot_test.cpp",
  ]

  cflags = [
    "-Dprivate=public",
    "-Dprotected=public",
  ]

  deps = [
    "${frameworks_module_ans_path}:ans_innerkits",
    "${services_path}/ans:libans",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
    "bundle_framework:appexecfwk_base",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"

  sanitize = {
    cfi = true
    cfi_cross_dso = true
    debug = false
  }
}
```

## Adding Multiple Test Files

```gn
ohos_unittest("module_test") {
  module_out_path = module_output_path

  include_dirs = [
    ".",
    "include",
    "/${services_path}/module/include",
    "${services_path}/module/test/unittest/mock/include",
  ]

  sources = [
    "test_file1.cpp",
    "test_file2.cpp",
    "test_file3.cpp",
  ]

  cflags = [
    "-Dprivate=public",
    "-Dprotected=public",
  ]

  deps = [
    "${frameworks_path}:module_innerkits",
    "${services_path}/module:libmodule:mock_source",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"
}
```

## Conditional Compilation

```gn
ohos_unittest("test_name") {
  module_out_path = module_output_path

  include_dirs = [
    ".",
    "include",
  ]

  sources = [
    "test_file.cpp",
  ]

  cflags = [
    "-Dprivate=public",
    "-Dprotected=public",
  ]

  defines = []

  # Add feature flags if needed
  if (distributed_notification_service_feature_original_distributed) {
    defines += [ "ANS_FEATURE_ORIGINAL_DISTRIBUTED" ]
    deps += [ "${services_path}/distributed:libans_distributed" ]
  }

  if (distributed_notification_service_feature_priority_notification) {
    defines += [ "ANS_FEATURE_PRIORITY_NOTIFICATION" ]
  }

  deps = [
    "${frameworks_path}:module_innerkits",
    "${services_path}/module:libmodule",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"
}
```

## Group Definition

```gn
group("unittest") {
  testonly = true
  deps = [
    ":test_name",
  ]
}
```

## Common Issues

### Issue: "undefined reference to 'ClassName'"

**Solution:** Add missing include paths:
```gn
include_dirs = [
  "/${services_path}/module/include",  # Add this
]
```

### Issue: "use_exceptions not recognized"

**Solution:** Ensure using correct syntax:
```gn
use_exceptions = true  # Correct
# Not: use_exceptions = "true"  # Wrong
```

### Issue: "mock source not found"

**Solution:** Add mock dependency:
```gn
deps = [
  "${services_path}/module:libmodule:mock:mock_source",  # Add this
]
```

## Best Practices

1. **Use descriptive target names** - `notification_slot_test` not `test`
2. **Group related tests** - Use `group()` to organize multiple test targets
3. **Enable sanitizers** - Add `sanitize` section for security
4. **Use consistent formatting** - Follow existing BUILD.gn style
5. **Document complex configurations** - Add comments for conditional compilation
