/**
 * @name CBOM - Go Mod Library Check
 * @description Part of a set of checks for FIPS Crytographic Bill of Materials.  Naively looks for usage of go crypto or openssl libraries.
 * @kind problem
 * @precision very-high
 * @id go/cbom-mod-library-check
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go

from GoModRequireLine gm
where gm.getPath().regexpMatch(".*crypto.*") or gm.getPath().regexpMatch(".*openssl.*")
select gm, gm.getPath() + " may be a possible crypto library"