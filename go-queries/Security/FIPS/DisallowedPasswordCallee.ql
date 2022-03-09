/**
 * @name CF - Disallowed Password Hashing Method
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-disallowed-password-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isDisallowedPasswordHashingAlgorithm(c.getCalleeName().toUpperCase())
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()