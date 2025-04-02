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
#ifndef _version_h

#define _version_h
#define year 2025
#define month 4
#define release 1
#define extraversion "adhoc"
#define rc_no 2
#define adhoc_no 0

#endif