import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, setCsrfToken, unwrap, type Me } from "./api/client";

/** The logged-in identity, or null when not logged in. */
export function useMe() {
  return useQuery<Me | null>({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        const me = await unwrap(api.GET("/me"));
        setCsrfToken(me.csrf_token);
        return me;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    retry: false,
    staleTime: 60_000,
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => unwrap(api.POST("/auth/logout")),
    onSettled: () => {
      setCsrfToken("");
      qc.setQueryData(["me"], null);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
    },
  });
}

/** Maps an error to a translation key under "errors.". */
export function errorKey(e: unknown): string {
  if (e instanceof ApiError) return e.code;
  if (e instanceof TypeError) return "network";
  return "unknown";
}
