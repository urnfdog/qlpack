/**
 * @name CBOM - Approved Encryption Method
 * @description Part of a set of checks for FIPS Crytographic Bill of Materials
 * @kind problem
 * @precision very-high
 * @id go/cbom-approved-encryption-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isApprovedEncryptionAlgorithm(c.getCalleeName().toUpperCase())
select c, c.getCalleeName().toUpperCase() + " detected in " + c.getFile() + " line " + c.getEndLine()