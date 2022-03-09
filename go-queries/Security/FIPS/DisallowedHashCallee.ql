/**
 * @name CF - Disallowed Hashing Method
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-disallowed-hashing-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isDisallowedHashingAlgorithm(c.getCalleeName().toUpperCase())
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()