/**
 * @name CBOM - Disallowed Password Hashing Method
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
where isDisallowedPasswordHashingAlgorithm(c.getCalleeName().toUpperCase())
select c.getCalleeName().toUpperCase(), "Cryptographic usage detected in " + c.getFile() + " line " + c.getEndLine()