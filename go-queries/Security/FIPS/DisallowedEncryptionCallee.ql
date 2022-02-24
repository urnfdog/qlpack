/**
 * @name CBOM - Disallowed Encryption Method
 * @description Part of a set of checks for FIPS Crytographic Bill of Materials
 * @kind problem
 * @precision very-high
 * @id go/cbom-disallowed-encryption-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isDisallowedEncryptionAlgorithm(c.getCalleeName().toUpperCase())
select c, c.getCalleeName().toUpperCase() + " detected in " + c.getFile() + " line " + c.getEndLine()