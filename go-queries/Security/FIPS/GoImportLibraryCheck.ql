/**
 * @name CBOM - Go Import Library Check
 * @description Reveals usages of go/crypto and a variety of go openssl for FIPS compliance purposes
 * @kind problem
 * @precision very-high
 * @id go/cbom-import-library-check
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go

from ImportSpec i
where i.getPath().regexpMatch("crypto/.*") or i.getPath().regexpMatch(".*openssl.*")
select i, "Possible crypto import: " + i.getPath()
