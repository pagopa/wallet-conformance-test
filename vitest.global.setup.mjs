import * as tls from "node:tls";

/**
 * For tests, configure Node's default TLS CA trust store to use the system CA certificates.
 */
tls.setDefaultCACertificates(tls.getCACertificates("system"));