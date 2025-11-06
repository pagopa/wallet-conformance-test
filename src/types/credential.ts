import { IssuerSignedDocument } from "@auth0/mdl";
import { SdJwt } from ".";

/**
 * A type alias representing a digital credential, which can be either an MdocCredential or an SdJwtCredential.
 *
 * This union type allows for flexible handling of different credential formats within the application,
 * enabling functions to accept and process credentials of varying structures.
 */
export type Credential = MdocCredential | SdJwtCredential;

/**
 * Represents a mobile document (mdoc) credential.
 *
 * This interface defines the structure for an mdoc credential, including the parsed document itself,
 * an array of subject identifiers (subs), and a type identifier.
 */
interface MdocCredential {
  /**
   * The parsed mdoc, represented as an `IssuerSignedDocument` object.
   */
  credential: IssuerSignedDocument;
  /**
   * An array of subject identifiers (`subs`) found within the mdoc.
   */
  subs: string[];
  /**
   * The type of the credential, fixed to `"mso_mdoc"`.
   */
  typ: "mso_mdoc";
}

/**
 * Represents a Selective Disclosure JWT (SD-JWT) credential.
 *
 * This interface defines the structure for an SD-JWT credential, including the parsed SD-JWT,
 * an array of subject identifiers (subs), and a type identifier.
 */
interface SdJwtCredential {
  /**
   * The parsed SD-JWT, represented as a `SdJwt` object.
   */
  credential: SdJwt;
  /**
   * An array of subject identifiers (`subs`) found within the SD-JWT.
   */
  subs: string[];
  /**
   * The type of the credential, fixed to `"dc+sd-jwt"`.
   */
  typ: "dc+sd-jwt";
}
