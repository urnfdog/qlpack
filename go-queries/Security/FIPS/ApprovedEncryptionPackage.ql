/**
 * @name CBOM - Approved Encryption Package
 * @description Part of a set of checks for FIPS Crytographic Bill of Materials
 * @kind problem
 * @precision very-high
 * @id go/cryptographic-bill-of-materials
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isApprovedEncryptionAlgorithm(c.getTarget().getPackage().getName().toUpperCase())
select c, c.getTarget().getPackage().getName().toUpperCase() + " detected in " + c.getFile() + " line " + c.getEndLine()