/**
 * @name Crytographic Bill of Materials
 * @description Listing of cryptographic functions used in the system
 * @kind path-problem
 * @precision very-high
 * @id go/cryptographic-bill-of-materials
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoBOMCustomizations::AllCryptoAlgorithm
import DataFlow::PathGraph

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "$@ is likely a cryptographic algorithm acting on sensitive data",
  source.getNode(), "Sensitive data"
