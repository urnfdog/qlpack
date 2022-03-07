/**
 * @name CBOM - Disallowed Hashing Expression
 * @description Part of a set of checks for cryptographic footprint - this is currently too broad and will likely result in duplicate results - trying to find usage of constants but not showing up
 * @kind problem
 * @precision very-high
 * @id go/cbom-disallowed-hashing-method
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import FIPSCryptoLibraries::AlgorithmNames

from ValueExpr cn
where isDisallowedHashingAlgorithm(cn.toString().toUpperCase())
select cn, "Possible use of " + cn.toString() + " detected in " + cn.getLocation()