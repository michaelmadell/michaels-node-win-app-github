// version_info.h
#pragma once

#include "version.h"

// Helper macros to convert numbers to strings for the resource compiler
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Define the file and product versions in the format required by VERSIONINFO
// e.g., 2025,8,1,2
#define VER_FILE_VERSION            VERSION_YEAR_1,VERSION_YEAR_2,VERSION_MONTH,VERSION_RELEASE
#define VER_PRODUCT_VERSION         VERSION_YEAR_1,VERSION_YEAR_2,VERSION_MONTH,VERSION_RELEASE

// Define the file and product versions as strings
// e.g., "2025.8.1.2"
#define VER_FILE_VERSION_STR        TOSTRING(VERSION_YEAR_1) "." TOSTRING(VERSION_YEAR_2) "." TOSTRING(VERSION_MONTH) "." TOSTRING(VERSION_RELEASE)
#define VER_PRODUCT_VERSION_STR     TOSTRING(VERSION_YEAR_1) "." TOSTRING(VERSION_YEAR_2) "." TOSTRING(VERSION_MONTH) "." TOSTRING(VERSION_RELEASE)
