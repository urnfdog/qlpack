/**
 * @name CF - Miscellaneous Crypto Method
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-miscellaneous-crypto-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isMiscellaneousToBeFlagged(c.getCalleeName().toUpperCase())
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()