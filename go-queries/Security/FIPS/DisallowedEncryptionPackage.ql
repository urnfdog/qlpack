/**
 * @name CF - Disallowed Encryption Package
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-disallowed-encryption-package
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isDisallowedEncryptionAlgorithm(c.getTarget().getPackage().getName().toUpperCase())
select c, c.getTarget().getPackage().getName().toUpperCase() + " detected in " + c.getFile() + " line " + c.getEndLine()