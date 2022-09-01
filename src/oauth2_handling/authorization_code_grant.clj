(ns oauth2-handling.authorization-code-grant
  (:require [clojure.string :as str])
  (:import (java.net URI URLEncoder)
           (java.util Base64)))

(defn- encode [^String s]
  (URLEncoder/encode s "US-ASCII"))

(defn- query
  "Add query parameters to `uri`. The query parameters will be encoded
  per <https://www.rfc-editor.org/rfc/rfc6749#appendix-B>."
  [uri query-params]
  ;; impl note: currently uri is a string, but this fn could be a
  ;; protocol function with impls for `java.net.URI`,
  ;; <https://github.com/lambdaisland/uri>, etc.
  (str uri \?
       (str/join \& (map (fn [[k v]] (str k \= (encode v))) query-params))))

(defn redirect-uri
  "Make a redirect URI appropriate for an authorization request or an
  access token request's redirect_uri."
  [base-redirect-uri next]
  (if next
    (query base-redirect-uri {"next" next})
    base-redirect-uri))

(defn authorization-request-uri
  "Construct the authorization request URI per
  <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1>."
  [{:keys [authorization-uri client-id base-redirect-uri]}
   & {:keys [next scopes csrf-state]}]
  (query authorization-uri
         (cond-> {"response_type" "code", "client_id" client-id}
           base-redirect-uri (assoc "redirect_uri"
                                    (redirect-uri base-redirect-uri next))
           (seq scopes) (assoc "scope" (str/join \space scopes))
           csrf-state (assoc "state" csrf-state))))

(defn access-token-request
  "An HTTP request to trade the `code` for an access token as per
  <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3>."
  [{:keys [access-token-uri client-id client-secret base-redirect-uri]}
   code
   & {:keys [next]}]
  ;; TODO other params

  ;; this an attempt to be HTTP client agnostic. I'm presuming we take
  ;; this result and give it to a protocol fn like `http/execute`
  (merge {:request-method :post
          :query-params {}
          :form-params {"grant_type" "authorization_code"
                        "code" code
                        "redirect_uri" (redirect-uri base-redirect-uri next)
                        "client_id" client-id}}
         (when client-secret
           ;; <https://www.rfc-editor.org/rfc/rfc6749#section-2.3>. Although
           ;; the standard suggests that other ways of authenticating
           ;; the client are possible, supporting HTTP basic
           ;; authentication
           ;; (<https://www.rfc-editor.org/rfc/rfc2617>) is required.
           {:headers {"Authorization"
                      (as-> (format "%s:%s" client-id client-secret) %
                        (.getBytes % "UTF-8")
                        (.encode (Base64/getEncoder) %)
                        (str "Basic " %))}})))

(defn authorization-response-handler
  "Make a Ring handler to handle the authorization response from the
  authorization server. Install the handler under e.g. GET /login.

  `redirect` is a function that, given a Ring request, extracts the
  URI that's used to redirect the user, via a 302 Found, to

  Requires `ring.middleware.params/wrap-params`. Requires
  `ring.middleware.session/wrap-session`, and that the `request`'s
  `:session` includes `::expected-state`."
  [{:as oauth-config :keys [client-id base-redirect-uri]}]
  (fn [{:as request
        {:as session ::keys [expected-state]} :session
        {:strs [error state code next]} :query-params}]
    ;; it's possible that I may want to use
    ;; `ring.middleware.params/assoc-query-params` myself so that I
    ;; can specify the encoding.
    (cond
      ;; <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1>
      error {:status 400}                 ; TODO improve
      (not= state expected-state) {:status 400}
      :else
      {:status 302
       :headers {"Location" next}
       :session
       (assoc
        session
        ::access-token (access-token-request oauth-config code :next next))})))
