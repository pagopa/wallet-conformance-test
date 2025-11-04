import { MDoc } from "@auth0/mdl";
import z from "zod";

export interface Mdoc {
  document: MDoc;
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
  valueDigests: z.map(z.string(), z.map(z.number().positive(), z.string())),
  version: z.string(),
});
