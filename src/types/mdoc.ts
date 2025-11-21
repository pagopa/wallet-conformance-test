import { Tagged } from "cbor";
import z from "zod";

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
