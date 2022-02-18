/**
 * @name Crytographic Bill of Materials
 * @description Listing of cryptographic functions used in the system
 * @kind problem
 * @precision very-high
 * @id go/cryptographic-bill-of-materials
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

// This is too specific - we're missing pkg/security/probe/constantfetch/fetcher.go: hasher:   md5.New()
// Need to also find expressions, maybe?
from DataFlow::CallNode c
where isWeakHashingAlgorithm(c.getTarget().getPackage().getName().toUpperCase()) or isStrongHashingAlgorithm(c.getTarget().getPackage().getName().toUpperCase())
select c.getTarget().getPackage().getName(), "Cryptographic usage detected in " + c.getFile() + " and in line " + c.getEndLine()