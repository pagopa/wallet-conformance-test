import z from "zod";

export const zDateOrDateTime = z.union([z.iso.date(), z.iso.datetime()]);
