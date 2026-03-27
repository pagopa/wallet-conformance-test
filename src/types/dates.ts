import z from "zod";

export const zDateOrDateTime = z.union([
  z.string().date("Invalid date format"),
  z.string().datetime("Invalid datetime format"),
]);
