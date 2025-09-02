// cmc-yocto versioning file
// See https://ahkeng.atlassian.net/wiki/spaces/6GRW/pages/2434957323/How+do+I+build+a+release
// Release formatting has the following format:
// <YEAR>.<MONTH>.<RELEASE>_<EXTRAVERSION><RC_NO>
// Example: 2024.12.1_rc1
// EXTRAVERSION can be rc, adhoc or ga   [** MUST BE LOWER CASE **]
// 
// Please do not modify unless necessary !!
// no padded zeros in branch name or month e.g. 2025.4.1 not 2025.01.01
// 

#pragma once

#define VERSION_YEAR_1 20
#define VERSION_YEAR_2 25
#define VERSION_MONTH 8
#define VERSION_RELEASE 1
#define VERSION_EXTRAVERSION "rc"
#define VERSION_RC_NO 2
#define VERSION_ADHOC_NO 2

#define SERIAL_PORT "\\\\.\\COM3"

