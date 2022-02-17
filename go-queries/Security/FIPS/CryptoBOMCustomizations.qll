/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * sensitive information in all cryptographic algorithms,
 * as well as extension points for adding your own.
 */

import go
private import CryptoLibraries

/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * sensitive information in all cryptographic algorithms,
 * as well as extension points for adding your own.
 */
module AllCryptoAlgorithm {
  /**
   * A data flow source for sensitive information in all cryptographic algorithms.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for sensitive information in all cryptographic algorithms.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for sensitive information in all cryptographic algorithms.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  class ExprNode extends Source {
    ExprNode() { this.asExpr() instanceof Expr }
  }

  /**
   * An expression used by a weak cryptographic algorithm.
   */
  class AllCryptographicOperationSink extends Sink {
    AllCryptographicOperationSink() {
      exists(CryptographicOperation application |
        (application.getAlgorithm().isWeak() or
        application.getAlgorithm().isStrong()) and
        this.asExpr() = application.getInput()
      )
    }
  }

  /**
   * A configuration depicting taint flow from sensitive information to all cryptographic algorithms.
   */
  class Configuration extends TaintTracking::Configuration {
    Configuration() { this = "AllCryptoAlgorithm" }

    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    override predicate isSanitizer(DataFlow::Node node) {
      super.isSanitizer(node) or
      node instanceof Sanitizer
    }
  }
}
