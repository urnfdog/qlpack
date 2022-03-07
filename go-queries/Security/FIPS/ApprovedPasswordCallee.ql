/**
 * @name CF - Approved Password Hashing Method
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-password-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isApprovedPasswordHashingAlgorithm(c.getCalleeName().toUpperCase())
select c, c.getCalleeName().toUpperCase() + " detected in " + c.getFile() + " line " + c.getEndLine()