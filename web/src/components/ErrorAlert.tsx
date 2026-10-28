import { useTranslation } from "react-i18next";
import { ApiError } from "../api/client";
import { errorKey } from "../auth";
import { Alert } from "./ui";

/** Shows an API error: the first field message if there is one, else the translated code. */
export function ErrorAlert({ error }: { error: unknown }) {
  const { t } = useTranslation();
  if (!error) return null;
  const fieldErr = error instanceof ApiError ? error.problem?.errors?.[0] : undefined;
  const text = fieldErr
    ? `${fieldErr.field}: ${fieldErr.message}`
    : t(`errors.${errorKey(error)}`, { defaultValue: error instanceof ApiError ? error.message : t("errors.unknown") });
  return <Alert>{text}</Alert>;
}
