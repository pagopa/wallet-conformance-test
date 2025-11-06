import { IssuerSignedDocument } from "@auth0/mdl";
import { Tagged } from "cbor";
import z from "zod";

/**
 * Represents a mobile document (mdoc) along with its subjects.
 *
 * This interface encapsulates a parsed `IssuerSignedDocument` and an array of subject identifiers
 * (`subs`) extracted from the document. It is used to manage mdocs within the system after they
 * have been validated and processed.
 */
export interface Mdoc {
  /**
   * The parsed mobile document, represented as an `IssuerSignedDocument` object.
   */
  document: IssuerSignedDocument;
  /**
   * An array of subject identifiers (`subs`) found within the mdoc.
   */
  subs: string[];
}

export const mdocPayloadSchema = z.object({
  deviceKeyInfo: z.object({
    deviceKey: z.map(z.number(), z.any()),
    keyAuthorizations: z.map(z.string(), z.any()).optional(),
    keyInfo: z.map(z.number(), z.any()).optional(),
  }),
  digestAlgorithm: z.string(),
  docType: z.string(),
  status: z
    .object({
      status_list: z.object({
        idx: z.number(),
        uri: z.string().url(),
      }),
    })
    .optional(),
  validityInfo: z.object({
    signed: z.date(),
    validFrom: z.date(),
    validUntil: z.date(),
  }),
  valueDigests: z.map(
    z.string(),
    z.map(z.number().int().nonnegative(), z.instanceof(Buffer)),
  ),
  version: z.string(),
});

/**
 * Defines the Zod schema for validating the structure of an issuer-signed document within an mdoc.
 *
 * This schema specifies the expected data types for the `issuerAuth` and `nameSpaces` properties
 * of an issuer-signed document. It ensures that `issuerAuth` is a tuple of Buffers and that
 * `nameSpaces` is a record of string arrays, where each array contains Tagged CBOR items.
 * This validation is crucial for ensuring the integrity and correctness of the mdoc data.
 */
export const issuerSignedSchema = z.object({
  issuerAuth: z.tuple([
    z.instanceof(Buffer),
    z.map(z.number(), z.instanceof(Buffer)),
    z.instanceof(Buffer),
    z.instanceof(Buffer),
  ]),
  nameSpaces: z.record(z.string(), z.array(z.instanceof(Tagged))),
});
